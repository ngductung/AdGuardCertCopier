
package vn.ncvinh.systemcertinstaller

import android.app.AlertDialog
import android.content.ComponentName
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.CountDownTimer
import android.text.InputType
import android.widget.EditText
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import vn.ncvinh.systemcertinstaller.databinding.ActivityMainBinding
import com.topjohnwu.superuser.Shell
import java.io.ByteArrayInputStream
import java.io.File
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import android.util.Base64
import okhttp3.*
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.*
import java.io.BufferedOutputStream
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * App cài đặt chứng chỉ CA vào hệ thống Android (yêu cầu root/Magisk).
 *
 * Flow chính:
 * 1. Chọn file cert hoặc tải từ Burp Suite → chuyển về PEM → tính hash
 * 2. Nếu module Magisk đã tồn tại → copy cert trực tiếp vào destDir
 *    Nếu chưa → tạo zip module → install qua ksud/magisk
 * 3. Inject cert vào hệ thống (reboot hoặc hot-inject qua nsenter)
 */
class MainActivity : ComponentActivity() {

    private lateinit var binding: ActivityMainBinding

    // Đường dẫn module Magisk trên thiết bị
    private val moduleDir = "/data/adb/modules/adguardcert"
    private val destDir  = "$moduleDir/system/etc/security/cacerts"

    // HTTP client để tải cert từ Burp Suite
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()

    // ===================== Logging ======================

    /** Kiểm tra file có phải PKCS#12 dựa vào đuôi (.p12/.pfx). */
    private fun looksLikePkcs12(uri: Uri): Boolean {
        val name = uri.lastPathSegment?.lowercase() ?: return false
        return name.endsWith(".p12") || name.endsWith(".pfx")
    }

    /** Hiển thị dialog nhập mật khẩu PKCS#12 rồi xử lý cert. */
    private fun askPasswordAndProcess(uri: Uri) {
        val input = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            hint = "Mật khẩu PKCS#12"
        }
        AlertDialog.Builder(this)
            .setTitle("Nhập mật khẩu cho PKCS#12")
            .setView(input)
            .setPositiveButton("OK") { _, _ ->
                val pwd = input.text?.toString() ?: ""
                processAndCopy(uri, pwd)
            }
            .setNegativeButton("Hủy", null)
            .show()
    }

    // Buffer lưu log các lệnh shell để debug
    private val cmdLog = mutableListOf<String>()

    /** Thực thi lệnh shell qua root và ghi log tự động (lệnh, stdout, stderr, trạng thái). */
    private fun runShell(vararg commands: String): Shell.Result {
        val time = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())
        for (cmd in commands) {
            cmdLog.add("[$time] $ $cmd")
        }
        val result = Shell.cmd(*commands).exec()
        val tag = if (result.isSuccess) "OK" else "FAIL(${result.code})"
        result.out.forEach { cmdLog.add("[$time] stdout: $it") }
        result.err.forEach { cmdLog.add("[$time] stderr: $it") }
        cmdLog.add("[$time] [$tag]")
        cmdLog.add("")
        return result
    }

    /** Hiển thị dialog xem/xóa log các lệnh shell đã thực thi. */
    private fun showLogDialog() {
        if (cmdLog.isEmpty()) {
            Toast.makeText(this, "Chưa có log nào.", Toast.LENGTH_SHORT).show()
            return
        }
        val logText = cmdLog.joinToString("\n")
        val scrollView = android.widget.ScrollView(this)
        val textView = android.widget.TextView(this).apply {
            text = logText
            setTextIsSelectable(true)
            textSize = 12f
            setPadding(24, 24, 24, 24)
            setTypeface(android.graphics.Typeface.MONOSPACE)
        }
        scrollView.addView(textView)
        AlertDialog.Builder(this)
            .setTitle("Log (${cmdLog.size} dòng)")
            .setView(scrollView)
            .setPositiveButton("Đóng", null)
            .setNeutralButton("Xóa log") { _, _ ->
                cmdLog.clear()
                Toast.makeText(this, "Đã xóa log.", Toast.LENGTH_SHORT).show()
            }
            .show()
    }

    // ===================== Lifecycle ======================

    private val pickAny = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri == null) {
            setStatus("Đã huỷ.")
            return@registerForActivityResult
        }
        // PKCS#12 cần mật khẩu, các format khác thì xử lý trực tiếp
        if (looksLikePkcs12(uri)) {
            askPasswordAndProcess(uri)
        } else {
            processAndCopy(uri, null)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        Shell.enableVerboseLogging = false

        binding.btnPick.setOnClickListener {
            pickAny.launch(arrayOf(
                "application/x-x509-ca-cert",
                "application/pkix-cert",
                "application/x-pem-file",
                "application/x-pkcs12",
                "*/*"
            ))
        }
        binding.btnDownloadFromUrl.setOnClickListener { showBurpSuiteDownloadDialog() }
        binding.btnSaved.setOnClickListener { showSavedListAndInstall() }
        binding.btnCheckCerts.setOnClickListener { openTrustedCredentials() }
        binding.btnReboot.setOnClickListener { confirmAndReboot() }
        binding.btnViewLog.setOnClickListener { showLogDialog() }
    }

    override fun onDestroy() {
        super.onDestroy()
        httpClient.dispatcher.executorService.shutdown()
        httpClient.connectionPool.evictAll()
    }

    // ===================== Certificate installation ======================

    /**
     * Xử lý file chứng chỉ: chuyển đổi sang PEM, tính hash, cài vào hệ thống.
     * @param pkcs12Password mật khẩu nếu file là PKCS#12, null nếu không.
     */
    private fun processAndCopy(uri: Uri, pkcs12Password: String?) {
        try {
            setButtonsEnabled(false)
            val pemFile = ensurePemFromUri(uri, pkcs12Password)
            val cert = x509FromPemFile(pemFile)
            val hash = getSubjectHash(cert)
            val destPath = "$destDir/$hash.0"

            val result = installCert(pemFile, hash, destPath)

            if (result.isSuccess) {
                setStatus("Đã cài chứng chỉ thành công.\nĐường dẫn: $destPath")
                promptSaveCert(pemFile) {
                    if (binding.switchAutoReboot.isChecked) {
                        startRebootCountdown(3)
                    } else {
                        applyCertWithoutReboot()
                    }
                }
            } else {
                val err = (result.out + result.err).joinToString("\n")
                setStatus("Lỗi khi cài chứng chỉ.\n$err")
                setButtonsEnabled(true)
            }
        } catch (e: Exception) {
            setStatus("Lỗi: ${e.message ?: e.toString()}")
            setButtonsEnabled(true)
        }
    }

    /**
     * Cài cert vào hệ thống. Tối ưu: nếu module đã tồn tại (destDir có sẵn)
     * thì chỉ copy cert trực tiếp, không cần tạo zip và install lại module.
     */
    private fun installCert(pemFile: File, hash: String, destPath: String): Shell.Result {
        val moduleExists = Shell.cmd("[ -d \"$destDir\" ]").exec().isSuccess
        return if (moduleExists) {
            // Module đã cài → chỉ copy cert vào
            runShell(
                "cp \"${pemFile.absolutePath}\" \"$destPath\"",
                "chmod 0644 \"$destPath\"",
                "chown 0:0 \"$destPath\""
            )
        } else {
            // Chưa có module → tạo zip và install
            val zipFile = createModuleZip(pemFile, hash)
            installModuleFromZip(zipFile)
        }
    }

    /**
     * Tạo file zip Magisk module chứa:
     * - META-INF/com/google/android/update-binary: script cài đặt Magisk
     * - META-INF/com/google/android/updater-script: marker "#MAGISK"
     * - module.prop: metadata module (id, name, version)
     * - post-fs-data.sh: script chạy khi boot (bind-mount cert vào APEX)
     * - system/etc/security/cacerts/{hash}.0: file chứng chỉ PEM
     */
    private fun createModuleZip(pemFile: File, hash: String): File {
        val zipFile = File(cacheDir, "adguardcert-module.zip")
        ZipOutputStream(BufferedOutputStream(FileOutputStream(zipFile))).use { zos ->
            // META-INF - yêu cầu bởi Magisk để nhận diện module zip
            val metaFiles = listOf(
                "META-INF/com/google/android/update-binary",
                "META-INF/com/google/android/updater-script"
            )
            for (path in metaFiles) {
                zos.putNextEntry(ZipEntry(path))
                zos.write(assets.open(path).readBytes())
                zos.closeEntry()
            }

            // Module metadata
            val moduleProp = assets.open("module.prop").bufferedReader().use { it.readText() }
            zos.putNextEntry(ZipEntry("module.prop"))
            zos.write(moduleProp.toByteArray())
            zos.closeEntry()

            // Boot script - bind-mount cert vào hệ thống khi khởi động
            val postFsData = assets.open("post-fs-data.sh").bufferedReader().use { it.readText() }
            zos.putNextEntry(ZipEntry("post-fs-data.sh"))
            zos.write(postFsData.toByteArray())
            zos.closeEntry()

            // Chứng chỉ - đặt theo cấu trúc system overlay của Magisk
            zos.putNextEntry(ZipEntry("system/etc/security/cacerts/$hash.0"))
            zos.write(pemFile.readBytes())
            zos.closeEntry()
        }
        return zipFile
    }

    /**
     * Copy zip sang /data/local/tmp/ rồi install qua ksud (KernelSU).
     * Fallback sang magisk nếu ksud thất bại.
     * Giữ lại zip sau khi cài để debug.
     */
    private fun installModuleFromZip(zipFile: File): Shell.Result {
        val tmpZip = "/data/local/tmp/adguardcert-module.zip"
        runShell("cp \"${zipFile.absolutePath}\" \"$tmpZip\"")

        var result = runShell("ksud module install \"$tmpZip\"")
        if (!result.isSuccess) {
            result = runShell("magisk --install-module \"$tmpZip\"")
        }

        return result
    }

    // ===================== Burp Suite download ======================

    /** Hiển thị dialog nhập IP/Port để tải cert từ Burp Suite. */
    private fun showBurpSuiteDownloadDialog() {
        val container = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(50, 20, 50, 20)
        }

        val ipInput = EditText(this).apply {
            hint = "IP Address (ví dụ: 192.168.4.100)"
            inputType = InputType.TYPE_CLASS_TEXT
            setText("192.168.4.100")
        }

        val portInput = EditText(this).apply {
            hint = "Port (ví dụ: 8080)"
            inputType = InputType.TYPE_CLASS_NUMBER
            setText("8080")
        }

        container.addView(android.widget.TextView(this).apply {
            text = "IP Address:"
            setPadding(0, 0, 0, 10)
        })
        container.addView(ipInput)

        container.addView(android.widget.TextView(this).apply {
            text = "Port:"
            setPadding(0, 20, 0, 10)
        })
        container.addView(portInput)

        AlertDialog.Builder(this)
            .setTitle("Tải chứng chỉ từ Burp Suite")
            .setMessage("Nhập thông tin Burp Suite để tải chứng chỉ CA:")
            .setView(container)
            .setPositiveButton("Tải") { _, _ ->
                val ip = ipInput.text?.toString()?.trim() ?: ""
                val port = portInput.text?.toString()?.trim() ?: ""
                if (ip.isNotEmpty() && port.isNotEmpty()) {
                    downloadCertificateFromBurpSuite(ip, port)
                } else {
                    Toast.makeText(this, "Vui lòng nhập đầy đủ IP và Port", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("Hủy", null)
            .show()
    }

    /**
     * Tải cert CA từ Burp Suite qua HTTP (endpoint: http://IP:PORT/cert).
     * Burp Suite thường trả về định dạng DER.
     */
    private fun downloadCertificateFromBurpSuite(ip: String, port: String) {
        setButtonsEnabled(false)
        setStatus("Đang tải chứng chỉ từ Burp Suite ($ip:$port)...")

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val request = Request.Builder().url("http://$ip:$port/cert").build()
                val response = httpClient.newCall(request).execute()

                if (!response.isSuccessful) {
                    throw IOException(
                        "Không thể tải chứng chỉ. Mã lỗi: ${response.code}\n" +
                        "Kiểm tra: Burp Suite đang chạy, IP/Port đúng, Proxy listener đã bật."
                    )
                }

                val certData = response.body?.bytes()
                    ?: throw IOException("Phản hồi rỗng từ Burp Suite")

                // Lưu cert tạm rồi xử lý như file bình thường
                val tempFile = File(cacheDir, "burp_cert.tmp")
                tempFile.writeBytes(certData)

                runOnUiThread { processAndCopy(Uri.fromFile(tempFile), null) }
            } catch (e: Exception) {
                runOnUiThread {
                    setStatus("Lỗi khi tải chứng chỉ từ Burp Suite: ${e.message}")
                    setButtonsEnabled(true)
                }
            }
        }
    }

    // ===================== Reboot & inject ======================

    /** Đếm ngược rồi reboot thiết bị. */
    private fun startRebootCountdown(seconds: Int) {
        binding.tvCountdown.text = "Sẽ khởi động lại sau ${seconds}s..."
        object : CountDownTimer((seconds * 1000).toLong(), 1000L) {
            override fun onTick(msLeft: Long) {
                binding.tvCountdown.text = "Sẽ khởi động lại sau ${msLeft / 1000}s..."
            }
            override fun onFinish() {
                binding.tvCountdown.text = "Đang khởi động lại..."
                val res = runShell("svc power reboot || reboot || setprop sys.powerctl reboot")
                if (!res.isSuccess) {
                    Toast.makeText(this@MainActivity, "Không thể reboot tự động. Vui lòng reboot thủ công.", Toast.LENGTH_LONG).show()
                    setButtonsEnabled(true)
                }
            }
        }.start()
    }

    /** Dialog xác nhận trước khi reboot. */
    private fun confirmAndReboot() {
        AlertDialog.Builder(this)
            .setTitle("Xác nhận reboot")
            .setMessage("Bạn có chắc chắn muốn khởi động lại thiết bị?")
            .setPositiveButton("Reboot") { _, _ ->
                val res = runShell("svc power reboot || reboot || setprop sys.powerctl reboot")
                if (!res.isSuccess) {
                    Toast.makeText(this, "Không thể reboot. Vui lòng reboot thủ công.", Toast.LENGTH_LONG).show()
                }
            }
            .setNegativeButton("Hủy", null)
            .show()
    }

    /**
     * Inject cert vào hệ thống mà không cần reboot.
     * Sử dụng nsenter để bind-mount cert vào namespace của init (PID 1),
     * từ đó tất cả app mới khởi tạo sẽ thấy cert.
     */
    private fun applyCertWithoutReboot() {
        setStatus("Đang inject chứng chỉ vào hệ thống...")
        binding.tvCountdown.text = "⏳ Đang xử lý..."

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val systemCerts = "/system/etc/security/cacerts"
                val scriptPath = "/data/local/tmp/inject_cert.sh"

                // Copy inject script từ assets sang thiết bị
                val scriptContent = assets.open("inject_cert.sh").bufferedReader().use { it.readText() }
                val tempScript = File(cacheDir, "inject_cert.sh")
                tempScript.writeText(scriptContent)

                runShell(
                    "cp \"${tempScript.absolutePath}\" \"$scriptPath\"",
                    "chmod 755 \"$scriptPath\""
                )
                tempScript.delete()

                // Chạy inject script trong namespace của PID 1
                val result = runShell("nsenter -t 1 -m -- sh $scriptPath \"$destDir\"")
                runShell("rm -f $scriptPath")

                val success = runShell("nsenter -t 1 -m -- ls $systemCerts/*.0 2>/dev/null").isSuccess

                runOnUiThread {
                    if (success) {
                        setStatus("✅ Đã inject chứng chỉ thành công!\n\nChứng chỉ đã được áp dụng cho tất cả ứng dụng.")
                        binding.tvCountdown.text = "✅ Hoàn tất!"
                    } else {
                        val err = (result.out + result.err).joinToString("\n")
                        setStatus("❌ Lỗi khi inject chứng chỉ:\n$err")
                        binding.tvCountdown.text = "❌ Thất bại"
                    }
                    setButtonsEnabled(true)
                }
            } catch (e: Exception) {
                runOnUiThread {
                    setStatus("❌ Lỗi: ${e.message}")
                    binding.tvCountdown.text = "❌ Inject thất bại"
                    setButtonsEnabled(true)
                }
            }
        }
    }

    /** Mở trang Trusted Credentials trong Settings (hoặc fallback sang Security Settings). */
    private fun openTrustedCredentials() {
        try {
            startActivity(Intent().apply {
                component = ComponentName(
                    "com.android.settings",
                    "com.android.settings.Settings\$TrustedCredentialsSettingsActivity"
                )
            })
        } catch (_: Exception) {
            try {
                startActivity(Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS))
            } catch (e2: Exception) {
                Toast.makeText(this, "Không thể mở cài đặt chứng chỉ: ${e2.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun setButtonsEnabled(enabled: Boolean) {
        binding.btnPick.isEnabled = enabled
        binding.btnDownloadFromUrl.isEnabled = enabled
        binding.btnSaved.isEnabled = enabled
        binding.btnCheckCerts.isEnabled = enabled
        binding.btnReboot.isEnabled = enabled
    }

    private fun setStatus(msg: String) {
        binding.tvStatus.text = msg
    }

    // ===================== Saved certificates ======================

    private fun savedDir(): File = File(filesDir, "saved_certs").apply { if (!exists()) mkdirs() }

    /** Liệt kê cert đã lưu kèm MD5 hash (10 ký tự đầu) để phân biệt trùng tên. */
    private fun listSavedNames(): List<String> {
        val dir = savedDir()
        return dir.listFiles()
            ?.filter { it.isFile && it.name.endsWith(".pem") }
            ?.map { "${it.nameWithoutExtension} [${calculateMd5(it)}]" }
            ?.sorted() ?: emptyList()
    }

    private fun calculateMd5(file: File): String {
        val md = MessageDigest.getInstance("MD5")
        file.inputStream().use { fis ->
            val buffer = ByteArray(8192)
            var bytesRead: Int
            while (fis.read(buffer).also { bytesRead = it } != -1) {
                md.update(buffer, 0, bytesRead)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }.substring(0, 10)
    }

    /** Hỏi user có muốn lưu cert vừa cài để tái sử dụng không. */
    private fun promptSaveCert(pemFile: File, onDone: () -> Unit = {}) {
        val input = EditText(this).apply { hint = "Tên chứng chỉ (ví dụ: Burp CA)" }
        AlertDialog.Builder(this)
            .setTitle("Lưu chứng chỉ vừa cài?")
            .setView(input)
            .setPositiveButton("Lưu") { _, _ ->
                val name = sanitizeName(input.text?.toString() ?: "")
                try {
                    val dir = savedDir()
                    val target = File(dir, "$name.pem")
                    if (!dir.exists()) dir.mkdirs()
                    pemFile.copyTo(target, overwrite = true)
                    Toast.makeText(this, "Đã lưu: ${target.name}", Toast.LENGTH_SHORT).show()
                } catch (e: Exception) {
                    Toast.makeText(this, "Không lưu được: ${e.message}", Toast.LENGTH_LONG).show()
                } finally {
                    onDone()
                }
            }
            .setNegativeButton("Không") { _, _ -> onDone() }
            .setCancelable(false)
            .show()
    }

    private fun showSavedListAndInstall() {
        val names = listSavedNames()
        if (names.isEmpty()) {
            Toast.makeText(this, "Chưa có chứng chỉ nào được lưu.", Toast.LENGTH_SHORT).show()
            return
        }
        showCertManagementDialog(names)
    }

    /** Dialog quản lý cert đã lưu: tìm kiếm real-time, cài đặt, xóa. */
    private fun showCertManagementDialog(originalNames: List<String>) {
        val container = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(20, 20, 20, 20)
        }

        val searchInput = EditText(this).apply {
            hint = "Tìm kiếm chứng chỉ..."
            inputType = InputType.TYPE_CLASS_TEXT
            setPadding(16, 16, 16, 16)
        }
        container.addView(searchInput)

        container.addView(android.widget.Space(this).apply { minimumHeight = 20 })

        val listView = android.widget.ListView(this).apply {
            layoutParams = android.widget.LinearLayout.LayoutParams(
                android.widget.LinearLayout.LayoutParams.MATCH_PARENT,
                400
            )
        }
        container.addView(listView)

        var filteredNames = originalNames.toMutableList()
        val adapter = android.widget.ArrayAdapter(this, android.R.layout.simple_list_item_1, filteredNames)
        listView.adapter = adapter

        lateinit var dialog: AlertDialog

        // Lọc danh sách theo query real-time
        searchInput.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                val query = s?.toString()?.lowercase() ?: ""
                filteredNames.clear()
                filteredNames.addAll(
                    if (query.isEmpty()) originalNames
                    else originalNames.filter { it.lowercase().contains(query) }
                )
                adapter.notifyDataSetChanged()
            }
        })

        listView.setOnItemClickListener { _, _, position, _ ->
            if (position < filteredNames.size) {
                val selectedName = filteredNames[position]
                showCertOptionsDialog(selectedName, onInstall = {
                    dialog.dismiss()
                }, onDelete = {
                    val updatedNames = listSavedNames()
                    if (updatedNames.isEmpty()) {
                        Toast.makeText(this, "Không còn chứng chỉ nào được lưu.", Toast.LENGTH_SHORT).show()
                        dialog.dismiss()
                        return@showCertOptionsDialog
                    }
                    filteredNames.clear()
                    val currentQuery = searchInput.text?.toString()?.lowercase() ?: ""
                    filteredNames.addAll(
                        if (currentQuery.isEmpty()) updatedNames
                        else updatedNames.filter { it.lowercase().contains(currentQuery) }
                    )
                    adapter.notifyDataSetChanged()
                })
            }
        }

        dialog = AlertDialog.Builder(this)
            .setTitle("Quản lý chứng chỉ đã lưu (${originalNames.size} chứng chỉ)")
            .setView(container)
            .setNegativeButton("Đóng", null)
            .create()
        dialog.show()
    }

    private fun showCertOptionsDialog(certName: String, onInstall: () -> Unit, onDelete: () -> Unit) {
        val actualName = certName.substringBefore(" [")
        AlertDialog.Builder(this)
            .setTitle("Chọn thao tác cho: $actualName")
            .setItems(arrayOf("Cài đặt chứng chỉ", "Xóa chứng chỉ")) { _, which ->
                when (which) {
                    0 -> { installFromSaved(actualName); onInstall() }
                    1 -> confirmDeleteCert(actualName, onDelete)
                }
            }
            .setNegativeButton("Hủy", null)
            .show()
    }

    private fun confirmDeleteCert(certName: String, onActionComplete: () -> Unit) {
        AlertDialog.Builder(this)
            .setTitle("Xác nhận xóa")
            .setMessage("Bạn có chắc chắn muốn xóa chứng chỉ \"$certName\"?\n\nHành động này không thể hoàn tác.")
            .setPositiveButton("Xóa") { _, _ ->
                deleteSavedCert(certName)
                onActionComplete()
            }
            .setNegativeButton("Hủy", null)
            .show()
    }

    private fun deleteSavedCert(certName: String) {
        try {
            val file = File(savedDir(), "$certName.pem")
            if (file.exists() && file.delete()) {
                Toast.makeText(this, "Đã xóa chứng chỉ: $certName", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "Không thể xóa chứng chỉ: $certName", Toast.LENGTH_SHORT).show()
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Lỗi khi xóa chứng chỉ: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    /** Cài cert từ danh sách đã lưu. */
    private fun installFromSaved(name: String) {
        try {
            val f = File(savedDir(), "$name.pem")
            if (!f.exists()) {
                Toast.makeText(this, "Không tìm thấy: $name", Toast.LENGTH_SHORT).show()
                return
            }

            setButtonsEnabled(false)
            val cert = x509FromPemFile(f)
            val hash = getSubjectHash(cert)
            val destPath = "$destDir/$hash.0"

            val result = installCert(f, hash, destPath)

            if (result.isSuccess) {
                setStatus("Đã cài từ chứng chỉ đã lưu: $name\n$destPath")
                if (binding.switchAutoReboot.isChecked) {
                    startRebootCountdown(3)
                } else {
                    applyCertWithoutReboot()
                }
            } else {
                val err = (result.out + result.err).joinToString("\n")
                setStatus("Lỗi khi cài từ chứng chỉ đã lưu.\n$err")
                setButtonsEnabled(true)
            }
        } catch (e: Exception) {
            setStatus("Lỗi khi cài từ chứng chỉ đã lưu: ${e.message}")
            setButtonsEnabled(true)
        }
    }

    // ===================== Certificate parsing & conversion ======================

    /** Kiểm tra bytes có chứa PEM certificate block không. */
    private fun isPem(bytes: ByteArray): Boolean {
        val head = bytes.take(4096).toByteArray().toString(Charsets.US_ASCII)
        return head.contains("-----BEGIN CERTIFICATE-----")
    }

    /** Trích xuất tất cả PEM certificate blocks từ text. */
    private fun findPemBlocks(text: String): List<String> {
        val result = mutableListOf<String>()
        var idx = 0
        while (true) {
            val start = text.indexOf("-----BEGIN CERTIFICATE-----", idx)
            if (start < 0) break
            val end = text.indexOf("-----END CERTIFICATE-----", start)
            if (end < 0) break
            result.add(text.substring(start, end + "-----END CERTIFICATE-----".length))
            idx = end + "-----END CERTIFICATE-----".length
        }
        return result
    }

    /** Wrap base64 string thành dòng 64 ký tự (chuẩn PEM RFC 7468). */
    private fun wrap64(b64: String): String {
        val sb = StringBuilder()
        var i = 0
        while (i < b64.length) {
            val e = kotlin.math.min(i + 64, b64.length)
            sb.append(b64.substring(i, e)).append("\n")
            i = e
        }
        return sb.toString()
    }

    /** Chuyển DER bytes sang PEM string. */
    private fun derToPem(der: ByteArray): String {
        val b64 = Base64.encodeToString(der, Base64.NO_WRAP)
        return "-----BEGIN CERTIFICATE-----\n" + wrap64(b64) + "-----END CERTIFICATE-----\n"
    }

    private fun x509FromDer(der: ByteArray): X509Certificate {
        return CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(der)) as X509Certificate
    }

    private fun x509FromPemBlock(block: String): X509Certificate {
        val norm = block.replace("\r\n", "\n").replace("\r", "\n")
        return CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(norm.toByteArray(Charsets.US_ASCII))) as X509Certificate
    }

    /** Kiểm tra cert có phải Certificate Authority không (basicConstraints >= 0). */
    private fun isCA(cert: X509Certificate): Boolean {
        return try { cert.basicConstraints >= 0 } catch (_: Exception) { false }
    }

    /**
     * Tính subject hash giống OpenSSL subject_hash_old (-hash flag).
     * MD5 của encoded subject, lấy 4 bytes đầu convert sang little-endian hex.
     * Kết quả dùng làm tên file cert trong system store: {hash}.0
     */
    private fun getSubjectHash(cert: X509Certificate): String {
        val subject = cert.subjectX500Principal.encoded
        val hash = MessageDigest.getInstance("MD5").digest(subject)

        // 4 bytes đầu sang little-endian unsigned long
        val value = ((hash[0].toInt() and 0xff) or
                    ((hash[1].toInt() and 0xff) shl 8) or
                    ((hash[2].toInt() and 0xff) shl 16) or
                    ((hash[3].toInt() and 0xff) shl 24)).toLong() and 0xffffffffL

        return String.format("%08x", value)
    }

    private fun x509FromPemFile(file: File): X509Certificate {
        return x509FromPemBlock(file.readText(Charsets.US_ASCII))
    }

    /**
     * Đọc file chứng chỉ từ URI và chuyển về PEM file.
     * Thử theo thứ tự: PEM → DER → PKCS#12.
     * Nếu có nhiều cert trong file, ưu tiên chọn CA certificate.
     */
    private fun ensurePemFromUri(uri: Uri, pkcs12Password: String?): File {
        val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: throw IllegalStateException("Không đọc được dữ liệu từ file đã chọn.")

        val outFile = File(cacheDir, "upload_cert.pem")

        // Thử parse PEM
        if (isPem(bytes)) {
            val text = bytes.toString(Charsets.US_ASCII).replace("\r\n", "\n").replace("\r", "\n")
            val blocks = findPemBlocks(text)
            if (blocks.isEmpty()) throw IllegalArgumentException("PEM không chứa CERTIFICATE block.")
            var chosen: String? = null
            for (b in blocks) {
                try {
                    val x = x509FromPemBlock(b)
                    if (isCA(x)) { chosen = b; break }
                    if (chosen == null) chosen = b
                } catch (_: Exception) {}
            }
            outFile.writeText(chosen!! + "\n", Charsets.US_ASCII)
            return outFile
        }

        // Thử parse DER
        try {
            val pem = derToPem(x509FromDer(bytes).encoded)
            outFile.writeText(pem, Charsets.US_ASCII)
            return outFile
        } catch (_: Exception) { /* fallthrough */ }

        // Thử parse PKCS#12
        if (pkcs12Password != null) {
            val ks = KeyStore.getInstance("PKCS12")
            ks.load(ByteArrayInputStream(bytes), pkcs12Password.toCharArray())
            var chosenCert: X509Certificate? = null
            val aliases = ks.aliases()
            while (aliases.hasMoreElements()) {
                val cert = ks.getCertificate(aliases.nextElement())
                if (cert is X509Certificate) {
                    if (isCA(cert)) { chosenCert = cert; break }
                    if (chosenCert == null) chosenCert = cert
                }
            }
            if (chosenCert == null) throw IllegalArgumentException("Không tìm thấy certificate trong PKCS#12.")
            outFile.writeText(derToPem(chosenCert.encoded), Charsets.US_ASCII)
            return outFile
        }

        throw IllegalArgumentException("Định dạng không hỗ trợ hoặc cần mật khẩu PKCS#12.")
    }

    /** Loại bỏ ký tự đặc biệt khỏi tên file cert. */
    private fun sanitizeName(raw: String): String {
        var s = raw.trim().lowercase()
        s = s.map { c ->
            when {
                c in "/\\:*?\"<>|" || c.code in 0..31 -> '_'
                else -> c
            }
        }.joinToString("")
        s = s.replace(Regex("\\s+"), " ")
        if (s.isEmpty()) s = "cert-" + System.currentTimeMillis()
        if (s.length > 60) s = s.substring(0, 60)
        return s
    }
}

package vn.ncvinh.systemcertinstaller

import android.app.AlertDialog
import android.content.ComponentName
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.CountDownTimer
import android.os.Looper
import android.text.InputType
import android.util.TypedValue
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
import android.view.View
import okhttp3.*
import java.io.IOException
import java.io.FileOutputStream
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.concurrent.TimeUnit
import java.util.Date
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlinx.coroutines.*

class MainActivity : ComponentActivity() {

    private lateinit var binding: ActivityMainBinding
    private val logBuffer = StringBuilder()
    private val logFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
    private val maxLogChars = 20000
    private val verboseDiagnostics = false

    private val moduleDir = "/data/adb/modules/adguardcert"
    private val destDir  = "$moduleDir/system/etc/security/cacerts"
    private val moduleUpdateDir = "/data/adb/modules_update/adguardcert"
    private val updateDestDir = "$moduleUpdateDir/system/etc/security/cacerts"
    
    // OkHttp client for downloading certificates
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()

    private val pickAny = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri == null) {
            setStatus("Đã huỷ.")
            logActivity("Người dùng đã huỷ chọn file chứng chỉ")
            return@registerForActivityResult
        }
        logActivity("Đã chọn file chứng chỉ: ${uri.lastPathSegment ?: uri}")
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
        binding.tvLog.movementMethod = android.text.method.ScrollingMovementMethod.getInstance()
        binding.btnClearLog.setOnClickListener { clearLog() }
        binding.btnCopyLog.setOnClickListener { copyLogToClipboard() }
        logActivity("Ứng dụng đã khởi động")

        binding.btnPick.setOnClickListener {
            logActivity("Mở trình chọn chứng chỉ từ file")
            pickAny.launch(arrayOf(
                "application/x-x509-ca-cert",
                "application/pkix-cert",
                "application/x-pem-file",
                "application/x-pkcs12",
                "*/*"
            ))
        }
        binding.btnDownloadFromUrl.setOnClickListener {
            showBurpSuiteDownloadDialog()
        }
        binding.btnSaved.setOnClickListener {
            logActivity("Mở danh sách chứng chỉ đã lưu")
            showSavedListAndInstall()
        }
        binding.btnCheckCerts.setOnClickListener {
            logActivity("Người dùng mở màn hình Trusted Credentials")
            openTrustedCredentials()
        }
        binding.btnReboot.setOnClickListener {
            logActivity("Người dùng yêu cầu reboot")
            confirmAndReboot()
        }
    }

    private fun looksLikePkcs12(uri: Uri): Boolean {
        val name = uri.lastPathSegment?.lowercase() ?: return false
        return name.endsWith(".p12") || name.endsWith(".pfx")
    }

    private fun askPasswordAndProcess(uri: Uri) {
        logActivity("File có vẻ là PKCS#12, yêu cầu nhập mật khẩu")
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

    private fun processAndCopy(uri: Uri, pkcs12Password: String?) {
        try {
            setButtonsEnabled(false)
            logActivity("Bắt đầu xử lý chứng chỉ đầu vào")

            if (!ensureRootAccess()) {
                setButtonsEnabled(true)
                return
            }

            val pemFile = ensurePemFromUri(uri, pkcs12Password)
            val cert = x509FromPemFile(pemFile)
            val hash = getSubjectHash(cert)
            logActivity("Đã chuyển đổi sang PEM và tính subject hash: $hash")

            if (!installCertificateAsKernelSuModule(pemFile, hash)) {
                setButtonsEnabled(true)
                return
            }

            setStatus("Cài module thành công! Đang tiến hành hot inject...")
            promptSaveCert(pemFile) {
                // Đổi luồng: Gọi Inject thay vì Countdown
                applyCertWithoutReboot(pemFile, hash)
            }
        } catch (e: Exception) {
            setStatus("Lỗi: ${e.message ?: e.toString()}")
            logActivity("Lỗi xử lý chứng chỉ: ${e.message ?: e.toString()}")
            setButtonsEnabled(true)
        }
    }

    private fun createModuleFiles(): Boolean {
        val modulePropContent = assets.open("module.prop").bufferedReader().use { it.readText() }
        val postFsDataContent = assets.open("post-fs-data.sh").bufferedReader().use { it.readText() }
        
        val tempModuleProp = File(cacheDir, "module.prop")
        val tempPostFsData = File(cacheDir, "post-fs-data.sh")
        
        tempModuleProp.writeText(modulePropContent)
        tempPostFsData.writeText(postFsDataContent)

        val result = runShellWithLog(
            "Cập nhật file module",
            "for base in \"$moduleDir\" \"$moduleUpdateDir\"; do if [ -d \"${'$'}base\" ]; then cp \"${tempModuleProp.absolutePath}\" \"${'$'}base/module.prop\"; chmod 0644 \"${'$'}base/module.prop\"; cp \"${tempPostFsData.absolutePath}\" \"${'$'}base/post-fs-data.sh\"; chmod 0755 \"${'$'}base/post-fs-data.sh\"; fi; done"
        )

        tempModuleProp.delete()
        tempPostFsData.delete()

        if (!result.isSuccess) {
            val err = (result.out + result.err).joinToString("\n")
            setStatus("Lỗi khi cập nhật file module.\n$err")
            logActivity("Cập nhật file module thất bại: ${err.take(200)}")
            return false
        }

        logActivity("Đã cập nhật file module.prop và post-fs-data.sh cho modules/modules_update")
        return true
    }

    private fun installCertificateAsKernelSuModule(pemFile: File, hash: String): Boolean {
        val activeExists = Shell.cmd("[ -d \"$destDir\" ]").exec().isSuccess
        val updateExists = Shell.cmd("[ -d \"$updateDestDir\" ]").exec().isSuccess
        if (activeExists || updateExists) {
            var writeAnyOk = false
            if (activeExists) {
                val activeDestPath = "$destDir/$hash.0"
                logActivity("Phát hiện module active, ghi trực tiếp: $activeDestPath")
                writeAnyOk = writeCertificateToModule(pemFile.absolutePath, activeDestPath) || writeAnyOk
            }
            if (updateExists) {
                val updateDestPath = "$updateDestDir/$hash.0"
                logActivity("Phát hiện module_update, ghi trực tiếp: $updateDestPath")
                writeAnyOk = writeCertificateToModule(pemFile.absolutePath, updateDestPath) || writeAnyOk
            }
            if (!writeAnyOk) {
                return false
            }
            cleanupUnusedModuleCerts(hash)
            return createModuleFiles()
        }

        val zipFile = File(cacheDir, "adguardcert-module.zip")
        return try {
            buildKernelSuModuleZip(zipFile, pemFile, hash)
            logActivity("Đã tạo gói ZIP KernelSU: ${zipFile.absolutePath}")

            if (installKernelSuModuleZip(zipFile)) {
                cleanupUnusedModuleCerts(hash)
                createModuleFiles()
            } else {
                val destPath = "$destDir/$hash.0"
                logActivity("Không cài được bằng ksud, chuyển sang cài trực tiếp module path")
                val writeOk = writeCertificateToModule(pemFile.absolutePath, destPath)
                if (!writeOk) {
                    false
                } else {
                    cleanupUnusedModuleCerts(hash)
                    createModuleFiles()
                }
            }
        } catch (e: Exception) {
            setStatus("Lỗi khi tạo gói cài đặt KernelSU. ${e.message}")
            logActivity("Tạo ZIP KernelSU thất bại: ${e.message}")
            false
        } finally {
            zipFile.delete()
        }
    }

    private fun buildKernelSuModuleZip(zipFile: File, pemFile: File, hash: String) {
        val modulePropContent = assets.open("module.prop").bufferedReader().use { it.readText() }
        val postFsDataContent = assets.open("post-fs-data.sh").bufferedReader().use { it.readText() }
        val customizeContent = """
            #!/system/bin/sh
            chmod 755 "${'$'}MODPATH/post-fs-data.sh"
        """.trimIndent() + "\n"

        ZipOutputStream(FileOutputStream(zipFile)).use { zip ->
            addZipTextEntry(zip, "module.prop", modulePropContent)
            addZipTextEntry(zip, "customize.sh", customizeContent)
            addZipTextEntry(zip, "post-fs-data.sh", postFsDataContent)
            addZipBinaryEntry(zip, "system/etc/security/cacerts/$hash.0", pemFile.readBytes())
        }
    }

    private fun addZipTextEntry(zip: ZipOutputStream, entryName: String, content: String) {
        addZipBinaryEntry(zip, entryName, content.toByteArray(Charsets.UTF_8))
    }

    private fun addZipBinaryEntry(zip: ZipOutputStream, entryName: String, content: ByteArray) {
        val entry = ZipEntry(entryName)
        zip.putNextEntry(entry)
        zip.write(content)
        zip.closeEntry()
    }

    private fun installKernelSuModuleZip(zipFile: File): Boolean {
        val daemonCandidates = listOf(
            "/data/adb/ksud",
            "/data/adb/ksu/bin/ksud",
            "ksud"
        )

        val stagedZipPath = "/data/local/tmp/adguardcert-module.zip"
        val stageResult = runShellWithLog(
            "Stage ZIP KernelSU",
            "cp \"${zipFile.absolutePath}\" \"$stagedZipPath\"",
            "chmod 0644 \"$stagedZipPath\""
        )
        if (!stageResult.isSuccess) {
            val stageError = (stageResult.out + stageResult.err).joinToString("\n").trim().ifBlank { "(no output)" }
            val diag = collectRootDiagnostics()
            setStatus("Lỗi khi chuẩn bị ZIP cài module KernelSU.\n$stageError")
            logActivity("Không copy được ZIP sang /data/local/tmp: ${stageError.take(200)}")
            if (diag.isNotBlank()) {
                logActivity("Diagnostic: ${diag.take(400)}")
            }
            return false
        }
        logActivity("Đã stage ZIP tại $stagedZipPath")

        val attemptLogs = mutableListOf<String>()
        try {
            for (daemonPath in daemonCandidates) {
                logActivity("Đang cài module bằng KernelSU: $daemonPath")

                val command = if (daemonPath == "ksud") {
                    "command -v ksud >/dev/null 2>&1 && ksud module install \"$stagedZipPath\" || { echo 'ksud_not_found_in_PATH'; exit 127; }"
                } else {
                    "if [ -x \"$daemonPath\" ]; then \"$daemonPath\" module install \"$stagedZipPath\"; else echo 'missing_or_not_executable:$daemonPath'; exit 127; fi"
                }

                val result = runShellWithLog(
                    "KernelSU install $daemonPath",
                    command
                )
                val output = (result.out + result.err).joinToString("\n").trim().ifBlank { "(no output)" }
                attemptLogs.add("$daemonPath => $output")

                if (result.isSuccess) {
                    logActivity("KernelSU cài module thành công bằng $daemonPath")
                    return true
                }
            }
        } finally {
            runShellWithLog("Dọn ZIP đã stage", "rm -f \"$stagedZipPath\"")
        }

        val errorText = "Không thể gọi ksud để cài module.\n" + attemptLogs.joinToString("\n")
        setStatus("Lỗi khi cài module KernelSU.\n$errorText")
        logActivity("KernelSU module install thất bại: ${errorText.take(200)}")
        return false
    }

    /**
     * Hàm Hot-Inject với tùy chọn hỏi người dùng Reboot
     */
    private fun applyCertWithoutReboot(certFile: File, hash: String) {
        setStatus("Đang tiến hành hot inject chứng chỉ vào hệ thống...")
        binding.tvCountdown.visibility = View.VISIBLE
        binding.tvCountdown.text = "⏳ Đang xử lý tiêm..."
        setButtonsEnabled(false)

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val scriptPath = "/data/local/tmp/inject_cert.sh"
                val tempHotInjectDir = "/data/local/tmp/hot_inject_certs"

                // 1. Copy inject script từ assets
                val scriptContent = assets.open("inject_cert.sh").bufferedReader().use { it.readText() }
                val tempScript = File(cacheDir, "inject_cert.sh")
                tempScript.writeText(scriptContent)

                if (verboseDiagnostics) {
                    captureHotInjectDiagnostics("before_prepare", hash, tempHotInjectDir)
                }

                // 2. Chuẩn bị file
                val prepareResult = runShellWithLog(
                    "Chuẩn bị dữ liệu Hot-Inject",
                    "cp \"${tempScript.absolutePath}\" \"$scriptPath\"",
                    "chmod 755 \"$scriptPath\"",
                    "rm -rf \"$tempHotInjectDir\"",
                    "mkdir -p \"$tempHotInjectDir\"",
                    "cp \"${certFile.absolutePath}\" \"$tempHotInjectDir/$hash.0\"",
                    "chmod 644 \"$tempHotInjectDir/$hash.0\""
                )
                tempScript.delete()

                if (!prepareResult.isSuccess) {
                    val prepErr = (prepareResult.out + prepareResult.err).joinToString("\n").ifBlank { "(no output)" }
                    throw IllegalStateException("Chuẩn bị inject thất bại: $prepErr")
                }

                if (verboseDiagnostics) {
                    captureHotInjectDiagnostics("after_prepare", hash, tempHotInjectDir)
                }

                // 3. Thực thi
                val result = runShellWithLog("Thực thi Hot-Inject", "$scriptPath \"$tempHotInjectDir\"")
                val hotInjectOutput = (result.out + result.err).joinToString("\n").ifBlank { "(no output)" }
                val hotInjectKey = extractHotInjectKeyLines(hotInjectOutput)
                if (hotInjectKey.isNotBlank()) {
                    logActivity("Hot-Inject key log:\n$hotInjectKey")
                }

                if (verboseDiagnostics) {
                    captureHotInjectDiagnostics("after_execute", hash, tempHotInjectDir)
                }

                // 4. Dọn dẹp
                runShellWithLog("Dọn dẹp Hot-Inject", "rm -f \"$scriptPath\"", "rm -rf \"$tempHotInjectDir\"")

                runOnUiThread {
                    cleanupAppTempFiles()
                    if (result.isSuccess) {
                        setStatus("✅ Hot inject hoàn tất! Hệ thống đã nhận chứng chỉ.")
                        if (binding.switchAutoReboot.isChecked) {
                            logActivity("Auto reboot đang bật, sẽ reboot sau 3 giây")
                            Toast.makeText(this@MainActivity, "Hot inject thành công. Thiết bị sẽ tự reboot sau 3 giây.", Toast.LENGTH_SHORT).show()
                            startRebootCountdown(3)
                        } else {
                            binding.tvCountdown.text = "✅ Hot inject Thành công!"
                            setButtonsEnabled(true)
                        }
                            
                    } else {
                        val err = hotInjectOutput
                        setStatus("❌ Lỗi khi hot inject chứng chỉ:\n$err\n\nVui lòng Khởi động lại thiết bị.")
                        binding.tvCountdown.text = "❌ Hot inject thất bại"

                        if (verboseDiagnostics) {
                            logActivity("Hot-Inject script output đầy đủ: ${err.take(3000)}")
                        }
                        
                        // Nếu tiêm xịt, gạ luôn reboot
                        AlertDialog.Builder(this@MainActivity)
                            .setTitle("Hot inject Thất Bại")
                            .setMessage("Hot inject thất bại do giới hạn hệ điều hành. Vui lòng Khởi động lại thiết bị để cài đặt qua Module KernelSU.")
                            .setPositiveButton("Reboot ngay") { _, _ -> startRebootCountdown(3) }
                            .setNegativeButton("Hủy", null)
                            .show()
                    }
                    setButtonsEnabled(true)
                }
            } catch (e: Exception) {
                runOnUiThread {
                    cleanupAppTempFiles()
                    setStatus("❌ Lỗi: ${e.message}")
                    binding.tvCountdown.text = "❌ Lỗi thực thi"
                    setButtonsEnabled(true)
                }
                if (verboseDiagnostics) {
                    logActivity("Exception Hot-Inject: ${e.stackTraceToString().take(3000)}")
                }
            }
        }
    }

    private fun captureStartupDiagnostics() {
        runShellWithLog(
            "Startup diagnostics",
            "id",
            "id -u",
            "uname -a 2>&1 || true",
            "getprop ro.product.manufacturer 2>&1 || true",
            "getprop ro.product.model 2>&1 || true",
            "getprop ro.build.fingerprint 2>&1 || true",
            "getprop ro.boot.vbmeta.device_state 2>&1 || true",
            "getenforce 2>&1 || true",
            "command -v ksud 2>&1 || true",
            "ls -l /data/adb 2>&1 || true",
            "ls -l /data/adb/modules 2>&1 || true",
            "mount | grep -E 'apex|conscrypt|cacerts' 2>&1 || true"
        )
    }

    private fun captureHotInjectDiagnostics(stage: String, hash: String, tempHotInjectDir: String) {
        runShellWithLog(
            "Hot-Inject diagnostics [$stage]",
            "echo 'diag_stage=$stage hash=$hash'",
            "id",
            "id -u",
            "getenforce 2>&1 || true",
            "ls -ld /apex/com.android.conscrypt/cacerts /system/etc/security/cacerts 2>&1 || true",
            "ls -l /apex/com.android.conscrypt/cacerts | head -n 8 2>&1 || true",
            "ls -l /system/etc/security/cacerts | head -n 8 2>&1 || true",
            "echo apex_count=$(ls -1 /apex/com.android.conscrypt/cacerts 2>/dev/null | wc -l)",
            "echo system_count=$(ls -1 /system/etc/security/cacerts 2>/dev/null | wc -l)",
            "ls -l /apex/com.android.conscrypt/cacerts/$hash.0 2>&1 || true",
            "ls -l /system/etc/security/cacerts/$hash.0 2>&1 || true",
            "ls -l '$tempHotInjectDir' 2>&1 || true",
            "test -f '$tempHotInjectDir/$hash.0' && echo 'target_cert_present=yes' || echo 'target_cert_present=no'",
            "mount | grep -E 'conscrypt|cacerts|cert_staging|hot_inject' 2>&1 || true",
            "cat /proc/1/mountinfo | grep -E 'conscrypt|cacerts|cert_staging|hot_inject' 2>&1 || true",
            "for p in ${'$'}(pidof zygote 2>/dev/null) ${'$'}(pidof zygote64 2>/dev/null); do echo \"zygote_pid=${'$'}p\"; readlink /proc/${'$'}p/ns/mnt 2>&1; cat /proc/${'$'}p/mountinfo | grep -E 'conscrypt|cacerts|cert_staging|hot_inject' | head -n 20 2>&1; done || true"
        )
    }

    private fun startRebootCountdown(seconds: Int) {
        binding.tvCountdown.visibility = View.VISIBLE
        binding.tvCountdown.text = "Sẽ khởi động lại sau ${seconds}s..."
        logActivity("Bắt đầu đếm ngược reboot: ${seconds}s")
        object : CountDownTimer((seconds * 1000).toLong(), 1000L) {
            override fun onTick(msLeft: Long) {
                val s = (msLeft / 1000).toInt()
                binding.tvCountdown.text = "Sẽ khởi động lại sau ${s}s..."
            }
            override fun onFinish() {
                binding.tvCountdown.text = "Đang khởi động lại..."
                logActivity("Đang gửi lệnh reboot")
                val res = runShellWithLog(
                    "Reboot tự động",
                    "svc power reboot || reboot || setprop sys.powerctl reboot"
                )
                if (!res.isSuccess) {
                    Toast.makeText(this@MainActivity, "Không thể reboot tự động. Vui lòng reboot thủ công.", Toast.LENGTH_LONG).show()
                    logActivity("Reboot tự động thất bại")
                    setButtonsEnabled(true)
                }
            }
        }.start()
    }

    private fun setButtonsEnabled(enabled: Boolean) {
        binding.btnPick.isEnabled = enabled
        binding.btnDownloadFromUrl.isEnabled = enabled
        binding.btnSaved.isEnabled = enabled
        binding.btnCheckCerts.isEnabled = enabled
        binding.btnReboot.isEnabled = enabled
    }

    private fun openTrustedCredentials() {
        try {
            logActivity("Mở Trusted Credentials trong Settings")
            val intent = Intent().apply {
                component = ComponentName(
                    "com.android.settings",
                    "com.android.settings.Settings\$TrustedCredentialsSettingsActivity"
                )
            }
            startActivity(intent)
        } catch (e: Exception) {
            try {
                startActivity(Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS))
            } catch (e2: Exception) {
                Toast.makeText(this, "Không thể mở cài đặt chứng chỉ: ${e2.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun confirmAndReboot() {
        AlertDialog.Builder(this)
            .setTitle("Xác nhận reboot")
            .setMessage("Bạn có chắc chắn muốn khởi động lại thiết bị?")
            .setPositiveButton("Reboot") { _, _ ->
                val res = runShellWithLog(
                    "Reboot thủ công",
                    "svc power reboot || reboot || setprop sys.powerctl reboot"
                )
                if (!res.isSuccess) {
                    Toast.makeText(this, "Không thể reboot. Vui lòng reboot thủ công.", Toast.LENGTH_LONG).show()
                }
            }
            .setNegativeButton("Hủy", null)
            .show()
    }

    private fun showBurpSuiteDownloadDialog() {
        val container = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(50, 20, 50, 20)
        }
        
        val ipInput = EditText(this).apply {
            hint = "IP Address (ví dụ: 192.168.4.113)"
            inputType = InputType.TYPE_CLASS_TEXT
            setText("192.168.4.113")
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

    private fun downloadCertificateFromBurpSuite(ip: String, port: String) {
        setButtonsEnabled(false)
        setStatus("Đang tải chứng chỉ từ Burp Suite ($ip:$port)...")
        logActivity("Đang tải chứng chỉ từ http://$ip:$port/cert")

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val certUrl = "http://$ip:$port/cert"
                val certData = downloadBurpSuiteCertificate(certUrl)

                runOnUiThread {
                    processBurpSuiteCertificateData(certData, ip, port)
                }
            } catch (e: Exception) {
                runOnUiThread {
                    setStatus("Lỗi khi tải chứng chỉ từ Burp Suite: ${e.message}")
                    logActivity("Tải Burp Suite thất bại: ${e.message}")
                    setButtonsEnabled(true)
                }
            }
        }
    }

    private suspend fun downloadBurpSuiteCertificate(certUrl: String): ByteArray = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(certUrl)
            .build()

        val response = httpClient.newCall(request).execute()
        if (!response.isSuccessful) {
            throw IOException("Không thể tải chứng chỉ từ Burp Suite. Kiểm tra:\n" +
                    "1. Burp Suite đang chạy\n" +
                    "2. IP và Port đúng\n" +
                    "3. Proxy listener đã bật\n" +
                    "Mã lỗi: ${response.code}")
        }
        
        response.body?.bytes() ?: throw IOException("Phản hồi rỗng từ Burp Suite")
    }

    private fun processBurpSuiteCertificateData(certData: ByteArray, ip: String, port: String) {
        var tempFile: File? = null
        try {
            tempFile = File(cacheDir, "burp_cert.tmp")
            tempFile.writeBytes(certData)
            logActivity("Đã nhận dữ liệu chứng chỉ từ Burp Suite, bắt đầu xử lý")
            processDownloadedCert(tempFile, sourceName = "Burp Suite ($ip:$port)")
        } catch (e: Exception) {
            setStatus("Lỗi khi xử lý chứng chỉ từ Burp Suite: ${e.message}")
            logActivity("Xử lý dữ liệu chứng chỉ Burp Suite thất bại: ${e.message}")
            setButtonsEnabled(true)
        } finally {
            tempFile?.delete()
        }
    }

    private fun processDownloadedCert(certFile: File, sourceName: String = "Downloaded Certificate") {
        try {
            val uri = Uri.fromFile(certFile)
            setStatus("Đang xử lý chứng chỉ từ $sourceName...")
            logActivity("Xử lý file chứng chỉ tải xuống từ $sourceName")
            processAndCopy(uri, null)
        } catch (e: Exception) {
            setStatus("Lỗi khi xử lý chứng chỉ từ $sourceName: ${e.message}")
            logActivity("Lỗi xử lý file tải xuống: ${e.message}")
            setButtonsEnabled(true)
        }
    }

    private fun sanitizeName(raw: String): String {
        var s = raw.trim().lowercase()
        s = s.map { c ->
            when {
                c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' ||
                        c == '"' || c == '<' || c == '>' || c == '|' || c.code in 0..31 -> '_'
                else -> c
            }
        }.joinToString("")
        s = s.replace(Regex("\\s+"), " ")
        if (s.isEmpty()) s = "cert-" + System.currentTimeMillis().toString()
        if (s.length > 60) s = s.substring(0, 60)
        return s
    }

    private fun savedDir(): File = File(filesDir, "saved_certs").apply { if (!exists()) mkdirs() }

    private fun listSavedNames(): List<String> {
        val dir = savedDir()
        return dir.listFiles()?.filter { it.isFile && it.name.endsWith(".pem") }?.map { file ->
            val md5 = calculateMd5(file)
            "${file.nameWithoutExtension} [$md5]"
        }?.sorted() ?: emptyList()
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

    private fun promptSaveCert(pemFile: File, onDone: () -> Unit = {}) {
        val sidePadding = TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            24f,
            resources.displayMetrics
        ).toInt()
        val topPadding = TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            8f,
            resources.displayMetrics
        ).toInt()

        val container = android.widget.FrameLayout(this).apply {
            setPadding(sidePadding, topPadding, sidePadding, 0)
        }

        val input = EditText(this).apply {
            hint = "Tên chứng chỉ (ví dụ: Burp CA)"
            layoutParams = android.widget.FrameLayout.LayoutParams(
                android.widget.FrameLayout.LayoutParams.MATCH_PARENT,
                android.widget.FrameLayout.LayoutParams.WRAP_CONTENT
            )
        }
        container.addView(input)

        AlertDialog.Builder(this)
            .setTitle("Lưu chứng chỉ vừa cài?")
            .setView(container)
            .setPositiveButton("Lưu") { _, _ ->
                val raw = input.text?.toString() ?: ""
                val name = sanitizeName(raw)
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
            logActivity("Chưa có chứng chỉ nào trong danh sách đã lưu")
            return
        }
        logActivity("Mở danh sách ${names.size} chứng chỉ đã lưu")
        showCertManagementDialog(names)
    }

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

        container.addView(android.widget.Space(this).apply {
            minimumHeight = 20
        })

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

        searchInput.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                val query = s?.toString()?.lowercase() ?: ""
                filteredNames.clear()
                if (query.isEmpty()) {
                    filteredNames.addAll(originalNames)
                } else {
                    filteredNames.addAll(originalNames.filter { it.lowercase().contains(query) })
                }
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
                    if (currentQuery.isEmpty()) {
                        filteredNames.addAll(updatedNames)
                    } else {
                        filteredNames.addAll(updatedNames.filter { it.lowercase().contains(currentQuery) })
                    }
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
                    0 -> {
                        installFromSaved(actualName)
                        onInstall()
                    }
                    1 -> {
                        confirmDeleteCert(actualName, onDelete)
                    }
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

    private fun installFromSaved(name: String) {
        try {
            val f = File(savedDir(), "$name.pem")
            if (!f.exists()) {
                Toast.makeText(this, "Không tìm thấy: $name", Toast.LENGTH_SHORT).show()
                logActivity("Không tìm thấy chứng chỉ đã lưu: $name")
                return
            }

            setButtonsEnabled(false)
            logActivity("Bắt đầu cài chứng chỉ đã lưu: $name")

            if (!ensureRootAccess()) {
                setButtonsEnabled(true)
                return
            }

            val cert = x509FromPemFile(f)
            val hash = getSubjectHash(cert)

            if (!installCertificateAsKernelSuModule(f, hash)) {
                setButtonsEnabled(true)
                return
            }

            setStatus("Đã cài module chứng chỉ: $name. Đang tiến hành hot inject...")
            logActivity("Cài từ chứng chỉ đã lưu thành công: $name, tiến hành inject")
            
            // Gọi hàm Hot-Inject
            applyCertWithoutReboot(f, hash)
        } catch (e: Exception) {
            setStatus("Lỗi khi cài từ chứng chỉ đã lưu: ${e.message}")
            logActivity("Lỗi khi cài chứng chỉ đã lưu: ${e.message}")
            setButtonsEnabled(true)
        }
    }

    private fun isPem(bytes: ByteArray): Boolean {
        val head = bytes.take(4096).toByteArray().toString(Charsets.US_ASCII)
        return head.contains("-----BEGIN CERTIFICATE-----")
    }

    private fun findPemBlocks(text: String): List<String> {
        val result = mutableListOf<String>()
        var idx = 0
        while (true) {
            val start = text.indexOf("-----BEGIN CERTIFICATE-----", idx)
            if (start < 0) break
            val end = text.indexOf("-----END CERTIFICATE-----", start)
            if (end < 0) break
            val block = text.substring(start, end + "-----END CERTIFICATE-----".length)
            result.add(block)
            idx = end + "-----END CERTIFICATE-----".length
        }
        return result
    }

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

    private fun derToPem(der: ByteArray): String {
        val b64 = Base64.encodeToString(der, Base64.NO_WRAP)
        return "-----BEGIN CERTIFICATE-----\n" + wrap64(b64) + "-----END CERTIFICATE-----\n"
    }

    private fun x509FromDer(der: ByteArray): X509Certificate {
        val cf = CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
    }

    private fun x509FromPemBlock(block: String): X509Certificate {
        val cf = CertificateFactory.getInstance("X.509")
        val norm = block.replace("\r\n", "\n").replace("\r", "\n")
        return cf.generateCertificate(ByteArrayInputStream(norm.toByteArray(Charsets.US_ASCII))) as X509Certificate
    }

    private fun isCA(cert: X509Certificate): Boolean {
        return try { cert.basicConstraints >= 0 } catch (_: Exception) { false }
    }

    private fun getSubjectHash(cert: X509Certificate): String {
        try {
            val subject = cert.subjectX500Principal.encoded
            val digest = MessageDigest.getInstance("MD5")
            val hash = digest.digest(subject)
            
            val value = ((hash[0].toInt() and 0xff) or
                        ((hash[1].toInt() and 0xff) shl 8) or
                        ((hash[2].toInt() and 0xff) shl 16) or
                        ((hash[3].toInt() and 0xff) shl 24)).toLong() and 0xffffffffL
            
            return String.format("%08x", value)
        } catch (e: Exception) {
            throw RuntimeException("Không thể tính subject hash: ${e.message}", e)
        }
    }

    private fun x509FromPemFile(file: File): X509Certificate {
        val pem = file.readText(Charsets.US_ASCII)
        return x509FromPemBlock(pem)
    }

    private fun ensurePemFromUri(uri: Uri, pkcs12Password: String?): File {
        val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: throw IllegalStateException("Không đọc được dữ liệu từ file đã chọn.")

        val outFile = File(cacheDir, "upload_cert.pem")

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

        try {
            val derX = x509FromDer(bytes)
            val pem = derToPem(derX.encoded)
            outFile.writeText(pem, Charsets.US_ASCII)
            return outFile
        } catch (_: Exception) { /* fallthrough */ }

        if (pkcs12Password != null) {
            val ks = KeyStore.getInstance("PKCS12")
            ks.load(ByteArrayInputStream(bytes), pkcs12Password.toCharArray())
            val aliases = ks.aliases()
            var chosenCert: X509Certificate? = null
            while (aliases.hasMoreElements()) {
                val al = aliases.nextElement()
                val cert = ks.getCertificate(al)
                if (cert is X509Certificate) {
                    if (isCA(cert)) { chosenCert = cert; break }
                    if (chosenCert == null) chosenCert = cert
                }
            }
            if (chosenCert == null) throw IllegalArgumentException("Không tìm thấy certificate trong PKCS#12.")
            val pem = derToPem(chosenCert.encoded)
            outFile.writeText(pem, Charsets.US_ASCII)
            return outFile
        }

        throw IllegalArgumentException("Định dạng không hỗ trợ hoặc cần mật khẩu PKCS#12.")
    }

    private fun setStatus(msg: String) {
        binding.tvStatus.text = msg
        logActivity(msg)
    }

    private fun cleanupAppTempFiles() {
        File(cacheDir, "upload_cert.pem").delete()
        File(cacheDir, "burp_cert.tmp").delete()
        File(cacheDir, "adguardcert-module.zip").delete()
    }

    private fun cleanupUnusedModuleCerts(activeHash: String) {
        runShellWithLog(
            "Dọn cert cũ trong module",
            "if [ -d \"$destDir\" ]; then find \"$destDir\" -maxdepth 1 -type f -name '*.0' ! -name '$activeHash.0' -delete; fi",
            "if [ -d \"$updateDestDir\" ]; then find \"$updateDestDir\" -maxdepth 1 -type f -name '*.0' ! -name '$activeHash.0' -delete; fi",
            "rm -f /data/local/tmp/adguardcert-module.zip"
        )
    }

    private fun writeCertificateToModule(sourcePath: String, destPath: String): Boolean {
        val result = runShellWithLog(
            "Ghi chứng chỉ vào module",
            "mkdir -p \"$destDir\"",
            "cp \"$sourcePath\" \"$destPath\"",
            "chmod 0644 \"$destPath\""
        )

        if (!result.isSuccess) {
            val err = (result.out + result.err).joinToString("\n")
            val diag = collectRootDiagnostics()
            setStatus("Lỗi khi ghi chứng chỉ vào module.\n$err")
            logActivity("Ghi chứng chỉ thất bại: ${err.take(200)}")
            if (diag.isNotBlank()) {
                logActivity("Diagnostic: ${diag.take(400)}")
            }
            return false
        }

        logActivity("Đã ghi chứng chỉ vào module: $destPath")
        return true
    }

    private val cmdLog = mutableListOf<String>()

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

    private fun ensureRootAccess(): Boolean {
        val result = runShellWithLog("Kiểm tra root", "id -u")
        val out = (result.out + result.err).joinToString("\n").trim()
        if (result.isSuccess && out == "0") {
            return true
        }

        setStatus("Không có quyền root hoặc root shell chưa sẵn sàng.")
        logActivity("Kiểm tra root thất bại. id -u = ${if (out.isBlank()) "(no output)" else out}")
        return false
    }

    private fun collectRootDiagnostics(): String {
        val result = runShellWithLog(
            "Thu thập root diagnostics",
            "id -u 2>&1",
            "ls -ld /data /data/local /data/local/tmp /data/adb /data/adb/modules 2>&1"
        )
        return (result.out + result.err).joinToString(" | ").trim()
    }

    private fun runShellWithLog(step: String, vararg commands: String): Shell.Result {
        logActivity("$step...")

        val result = Shell.cmd(*commands).exec()
        val out = result.out.joinToString("\\n").trim()
        val err = result.err.joinToString("\\n").trim()

        if (result.isSuccess) {
            logActivity("$step: OK (exit=${result.code})")
        } else {
            logActivity("$step: FAIL (exit=${result.code})")
            if (out.isNotBlank()) {
                logActivity("Chi tiết stdout: ${out.take(5000)}")
            }
            if (err.isNotBlank()) {
                logActivity("Chi tiết stderr: ${err.take(5000)}")
            }
            if (out.isBlank() && err.isBlank()) {
                logActivity("Lỗi shell: không có output")
            }
        }

        if (verboseDiagnostics && result.isSuccess) {
            if (out.isNotBlank()) {
                logActivity("$step stdout: ${out.take(5000)}")
            }
            if (err.isNotBlank()) {
                logActivity("$step stderr: ${err.take(5000)}")
            }
        }

        return result
    }

    private fun extractHotInjectKeyLines(output: String): String {
        val lines = output.lines().map { it.trim() }.filter { it.isNotEmpty() }
        val key = lines.filter {
            it.contains("ERR:") ||
            it.contains("Inject Success") ||
            it.contains("staged cert count")
        }
        if (key.isEmpty()) {
            return ""
        }
        return key.take(10).joinToString("\n")
    }

    private fun logActivity(message: String) {
        val line = "[${logFormat.format(Date())}] ${message.trim()}"
        if (Looper.myLooper() == Looper.getMainLooper()) {
            appendLogLine(line)
        } else {
            runOnUiThread { appendLogLine(line) }
        }
    }

    private fun appendLogLine(line: String) {
        if (logBuffer.isNotEmpty()) {
            logBuffer.append('\n')
        }
        logBuffer.append(line)
        if (logBuffer.length > maxLogChars) {
            logBuffer.delete(0, logBuffer.length - maxLogChars)
        }
        binding.tvLog.text = logBuffer.toString()
        binding.logScroll.post {
            binding.logScroll.fullScroll(View.FOCUS_DOWN)
        }
    }

    private fun clearLog() {
        logBuffer.clear()
        binding.tvLog.text = ""
        Toast.makeText(this, "Đã xoá log hoạt động", Toast.LENGTH_SHORT).show()
    }

    private fun copyLogToClipboard() {
        val text = logBuffer.toString().trim()
        if (text.isEmpty()) {
            Toast.makeText(this, "Chưa có log để copy", Toast.LENGTH_SHORT).show()
            return
        }

        val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("Activity log", text))
        Toast.makeText(this, "Đã copy log vào clipboard", Toast.LENGTH_SHORT).show()
        logActivity("Người dùng đã copy toàn bộ log")
    }

    override fun onDestroy() {
        super.onDestroy()
        httpClient.dispatcher.executorService.shutdown()
        httpClient.connectionPool.evictAll()
    }
}
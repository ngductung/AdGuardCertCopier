#!/system/bin/sh
# Inject certificates - robust namespace bind WITHOUT tmpfs (Fix for Meizu KernelSU)

STAGE_DIR="/data/adb/cert_staging"
SYSTEM_CERTS="/system/etc/security/cacerts"
APEX_CERTS="/apex/com.android.conscrypt/cacerts"
APEX_ORIGIN_GLOB="/apex/com.android.conscrypt@*/cacerts"
MODULE_CERTS="$1"
NSENTER_BIN="$(command -v nsenter 2>/dev/null)"
MOUNT_BIN="$(command -v mount 2>/dev/null)"

if [ -z "$NSENTER_BIN" ]; then
    NSENTER_BIN="/system/bin/nsenter"
fi
if [ -z "$MOUNT_BIN" ]; then
    MOUNT_BIN="/system/bin/mount"
fi

if [ -z "$MODULE_CERTS" ] || [ ! -d "$MODULE_CERTS" ]; then
    echo "ERR: missing module cert directory: $MODULE_CERTS"
    exit 2
fi

if [ ! -x "$NSENTER_BIN" ]; then
    echo "ERR: nsenter not found"
    exit 3
fi

# 1. Dọn dẹp & tìm nguồn chứng chỉ
APEX_ORIGIN="$(ls -d $APEX_ORIGIN_GLOB 2>/dev/null | head -n 1)"
count_files() {
    dir="$1"
    if [ -d "$dir" ]; then
        ls -1 "$dir" 2>/dev/null | wc -l
    else
        echo 0
    fi
}

MIN_CERT_COUNT=50
SOURCE_DIR=""
SOURCE_COUNT=0

ORIGIN_COUNT="$(count_files "$APEX_ORIGIN")"
APEX_COUNT="$(count_files "$APEX_CERTS")"
SYSTEM_COUNT="$(count_files "$SYSTEM_CERTS")"

if [ -n "$APEX_ORIGIN" ] && [ "$ORIGIN_COUNT" -ge "$MIN_CERT_COUNT" ]; then
    SOURCE_DIR="$APEX_ORIGIN"
    SOURCE_COUNT="$ORIGIN_COUNT"
elif [ "$APEX_COUNT" -ge "$MIN_CERT_COUNT" ]; then
    SOURCE_DIR="$APEX_CERTS"
    SOURCE_COUNT="$APEX_COUNT"
elif [ "$SYSTEM_COUNT" -ge "$MIN_CERT_COUNT" ]; then
    SOURCE_DIR="$SYSTEM_CERTS"
    SOURCE_COUNT="$SYSTEM_COUNT"
fi

echo "INFO: source=${SOURCE_DIR:-none} origin=$ORIGIN_COUNT apex=$APEX_COUNT system=$SYSTEM_COUNT"

if [ -z "$SOURCE_DIR" ]; then
    echo "ERR: no valid cert source with >=$MIN_CERT_COUNT files, abort inject"
    exit 6
fi

SECONTEXT=$(ls -Zd "$SOURCE_DIR" 2>/dev/null | awk '{print $1}')
if [ -z "$SECONTEXT" ] || [ "$SECONTEXT" = "?" ]; then
    SECONTEXT="u:object_r:system_security_cacerts_file:s0"
fi

# Đảm bảo unmount nếu trước đó bị treo
umount -l "$STAGE_DIR" 2>/dev/null
rm -rf "$STAGE_DIR"
mkdir -p -m 755 "$STAGE_DIR"

# LƯU Ý: ĐÃ XÓA BỎ LỆNH "mount -t tmpfs" TẠI ĐÂY
# Dùng trực tiếp thư mục vật lý /data/local/tmp/cert_staging để chứa file

# 2. Copy chứng chỉ vào thư mục vật lý
cp -af "$SOURCE_DIR"/. "$STAGE_DIR"/ || {
    echo "ERR: failed to copy base cert store from $SOURCE_DIR"
    exit 7
}

if [ -d "$MODULE_CERTS" ]; then
    cp -af "$MODULE_CERTS"/. "$STAGE_DIR"/ 2>/dev/null || true
fi

CERT_COUNT="$(count_files "$STAGE_DIR")"
echo "INFO: staged cert count=$CERT_COUNT"

if [ "$CERT_COUNT" -lt "$MIN_CERT_COUNT" ] || [ "$CERT_COUNT" -lt "$SOURCE_COUNT" ]; then
    echo "ERR: staged cert count too low after copy ($CERT_COUNT), abort inject"
    exit 8
fi

# 3. Set lại quyền & Ép SELinux context chuẩn
chown -R 0:0 "$STAGE_DIR"
chmod 644 "$STAGE_DIR"/* 2>/dev/null || true
chmod 755 "$STAGE_DIR"
chcon -R "$SECONTEXT" "$STAGE_DIR" 2>/dev/null || true

# 4. Inject vào namespace chính (zygote/init)
ZYGOTE_PID=$(pidof zygote || true)
ZYGOTE64_PID=$(pidof zygote64 || true)
OK_COUNT=0

bind_in_ns() {
    NS_PATH="$1"
    TARGET="$2"
    LABEL="$3"

    if [ -z "$NS_PATH" ] || [ -z "$TARGET" ]; then
        return 1
    fi

    "$NSENTER_BIN" --mount="$NS_PATH" -- "$MOUNT_BIN" --bind "$STAGE_DIR" "$TARGET" >/dev/null 2>&1
    RC=$?
    if [ "$RC" -eq 0 ]; then
        OK_COUNT=$((OK_COUNT+1))
        return 0
    fi
    return 1
}

for Z_PID in $ZYGOTE_PID $ZYGOTE64_PID; do
    if [ -n "$Z_PID" ]; then
        NS_PATH="/proc/$Z_PID/ns/mnt"
        bind_in_ns "$NS_PATH" "$APEX_CERTS" "zygote:$Z_PID:apex"
        bind_in_ns "$NS_PATH" "$SYSTEM_CERTS" "zygote:$Z_PID:system"
    fi
done

# Bind thêm init namespace
bind_in_ns "/proc/1/ns/mnt" "$APEX_CERTS" "init:apex"
bind_in_ns "/proc/1/ns/mnt" "$SYSTEM_CERTS" "init:system"

# 5. Inject cho các App đang chạy (Chạy ngầm để không bị block)
APP_PIDS=""
for Z_PID in $ZYGOTE_PID $ZYGOTE64_PID; do
    if [ -n "$Z_PID" ]; then
        CHILDREN=$(pgrep -P "$Z_PID" 2>/dev/null || true)
        APP_PIDS="$APP_PIDS $CHILDREN"
    fi
done

for PID in $APP_PIDS; do
    if [ -n "$PID" ]; then
        NS_PATH="/proc/$PID/ns/mnt"
        "$NSENTER_BIN" --mount="$NS_PATH" -- "$MOUNT_BIN" --bind "$STAGE_DIR" "$APEX_CERTS" >/dev/null 2>&1 &
        "$NSENTER_BIN" --mount="$NS_PATH" -- "$MOUNT_BIN" --bind "$STAGE_DIR" "$SYSTEM_CERTS" >/dev/null 2>&1 &
    fi
done
wait

if [ "$OK_COUNT" -le 0 ]; then
    echo "ERR: no namespace bind succeeded"
    exit 5
fi

echo "Inject Success! binds=$OK_COUNT"
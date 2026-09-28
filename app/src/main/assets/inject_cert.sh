#!/system/bin/sh
# Inject certificates - robust namespace bind WITHOUT tmpfs (Fix for Meizu KernelSU)

# Mỗi lần chạy dùng 1 thư mục staging riêng. KHÔNG xoá thư mục đang được bind
# ở namespace nào đó, nếu không các app đang chạy sẽ thấy cacerts rỗng.
STAGE_BASE="/data/adb/adgcert_stage"
STAGE_ID="$(date +%s)-$$"
STAGE_DIR="$STAGE_BASE/$STAGE_ID"
# Mẫu nhận diện các bind do script này tạo (gồm cả bản cũ dùng /data/adb/cert_staging)
OUR_MOUNT_PATTERN="adgcert_stage|cert_staging"

SYSTEM_CERTS="/system/etc/security/cacerts"
APEX_CERTS="/apex/com.android.conscrypt/cacerts"
APEX_ORIGIN_GLOB="/apex/com.android.conscrypt@*/cacerts"
MODULE_CERTS="$1"
NSENTER_BIN="$(command -v nsenter 2>/dev/null)"
MOUNT_BIN="$(command -v mount 2>/dev/null)"
UMOUNT_BIN="$(command -v umount 2>/dev/null)"

# Android luôn có hơn 100 CA hệ thống. Nguồn ít hơn ngưỡng này coi như hỏng,
# bind nó lên sẽ xoá sạch CA store của mọi app.
MIN_CERT_COUNT=50

if [ -z "$NSENTER_BIN" ]; then
    NSENTER_BIN="/system/bin/nsenter"
fi
if [ -z "$MOUNT_BIN" ]; then
    MOUNT_BIN="/system/bin/mount"
fi
if [ -z "$UMOUNT_BIN" ]; then
    UMOUNT_BIN="/system/bin/umount"
fi

if [ -z "$MODULE_CERTS" ] || [ ! -d "$MODULE_CERTS" ]; then
    echo "ERR: missing module cert directory: $MODULE_CERTS"
    exit 2
fi

if [ ! -x "$NSENTER_BIN" ]; then
    echo "ERR: nsenter not found"
    exit 3
fi

# 1. Tìm nguồn chứng chỉ gốc
APEX_ORIGIN="$(ls -d $APEX_ORIGIN_GLOB 2>/dev/null | head -n 1)"
count_files() {
    dir="$1"
    if [ -n "$dir" ] && [ -d "$dir" ]; then
        ls -1 "$dir" 2>/dev/null | wc -l
    else
        echo 0
    fi
}

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

mkdir -p -m 755 "$STAGE_BASE"
mkdir -p -m 755 "$STAGE_DIR" || {
    echo "ERR: cannot create staging dir $STAGE_DIR"
    exit 4
}

abort_stage() {
    rm -rf "$STAGE_DIR"
    exit "$1"
}

# 2. Copy chứng chỉ vào thư mục staging
cp -af "$SOURCE_DIR"/. "$STAGE_DIR"/ || {
    echo "ERR: failed to copy base cert store from $SOURCE_DIR"
    abort_stage 7
}

cp -af "$MODULE_CERTS"/. "$STAGE_DIR"/ || {
    echo "ERR: failed to copy module certs from $MODULE_CERTS"
    abort_stage 7
}

for f in "$MODULE_CERTS"/*; do
    [ -f "$f" ] || continue
    if [ ! -f "$STAGE_DIR/${f##*/}" ]; then
        echo "ERR: module cert ${f##*/} missing in staging"
        abort_stage 7
    fi
done

CERT_COUNT="$(count_files "$STAGE_DIR")"
echo "INFO: staged cert count=$CERT_COUNT"

if [ "$CERT_COUNT" -lt "$MIN_CERT_COUNT" ] || [ "$CERT_COUNT" -lt "$SOURCE_COUNT" ]; then
    echo "ERR: staged cert count too low after copy ($CERT_COUNT), abort inject"
    abort_stage 8
fi

# 3. Set lại quyền & Ép SELinux context chuẩn
chown -R 0:0 "$STAGE_DIR"
chmod 644 "$STAGE_DIR"/* 2>/dev/null || true
chmod 755 "$STAGE_DIR"
chcon -R "$SECONTEXT" "$STAGE_DIR" 2>/dev/null || true

# 4. Bind vào namespace. Trước khi bind, gỡ các lớp bind cũ do script này tạo
# ở target đó để không chồng mount mỗi lần chạy lại.
unbind_ours() {
    PID="$1"
    TARGET="$2"
    i=0
    while [ "$i" -lt 10 ]; do
        TOP="$(grep " $TARGET " "/proc/$PID/mountinfo" 2>/dev/null | tail -n 1)"
        echo "$TOP" | grep -qE "$OUR_MOUNT_PATTERN" || return 0
        "$NSENTER_BIN" --mount="/proc/$PID/ns/mnt" -- "$UMOUNT_BIN" "$TARGET" >/dev/null 2>&1 || return 1
        i=$((i+1))
    done
}

bind_one() {
    PID="$1"
    TARGET="$2"
    unbind_ours "$PID" "$TARGET"
    "$NSENTER_BIN" --mount="/proc/$PID/ns/mnt" -- "$MOUNT_BIN" --bind "$STAGE_DIR" "$TARGET" >/dev/null 2>&1
}

ZYGOTE_PID=$(pidof zygote || true)
ZYGOTE64_PID=$(pidof zygote64 || true)
OK_COUNT=0

for P in $ZYGOTE_PID $ZYGOTE64_PID 1; do
    [ -n "$P" ] || continue
    bind_one "$P" "$APEX_CERTS" && OK_COUNT=$((OK_COUNT+1))
    bind_one "$P" "$SYSTEM_CERTS" && OK_COUNT=$((OK_COUNT+1))
done

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
        ( bind_one "$PID" "$APEX_CERTS"; bind_one "$PID" "$SYSTEM_CERTS" ) &
    fi
done
wait

if [ "$OK_COUNT" -le 0 ]; then
    echo "ERR: no namespace bind succeeded"
    abort_stage 5
fi

# 6. Dọn các thư mục staging cũ không còn được mount ở bất kỳ namespace nào
for d in "$STAGE_BASE"/*; do
    [ -d "$d" ] || continue
    name="${d##*/}"
    [ "$name" = "$STAGE_ID" ] && continue
    if ! cat /proc/[0-9]*/mountinfo 2>/dev/null | grep -q "adgcert_stage/$name"; then
        rm -rf "$d"
    fi
done

echo "Inject Success! binds=$OK_COUNT"

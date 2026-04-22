#!/system/bin/sh

exec > /data/local/tmp/adguardcert.log
exec 2>&1

set -x
echo "ADGCERT_POST_FS_VERSION=2026-04-23-r2"

MODDIR=${0%/*}
SYSTEM_CERTS=/system/etc/security/cacerts
APEX_CERTS=/apex/com.android.conscrypt/cacerts

set_context() {
    [ "$(getenforce)" = "Enforcing" ] || return 0

    default_selinux_context=u:object_r:system_file:s0
    selinux_context=$(ls -Zd $1 | awk '{print $1}')

    if [ -n "$selinux_context" ] && [ "$selinux_context" != "?" ]; then
        chcon -R $selinux_context $2
    else
        chcon -R $default_selinux_context $2
    fi
}

CERTS_DIR=${MODDIR}/system/etc/security/cacerts
TMP_CA_DIR=/data/local/tmp/adg-ca-copy

if ! [ -d "${CERTS_DIR}" ] || [ -z "$(ls -A ${CERTS_DIR})" ]; then
    exit 0
fi

chown -R 0:0 ${CERTS_DIR}
set_context ${SYSTEM_CERTS} ${CERTS_DIR}

# Android 14 support
if [ -d ${APEX_CERTS} ]; then
    rm -rf ${TMP_CA_DIR}
    mkdir -p ${TMP_CA_DIR}
    mount -t tmpfs -o mode=755 tmpfs ${TMP_CA_DIR}
    chmod 755 ${TMP_CA_DIR}
    cp -f ${APEX_CERTS}/* ${TMP_CA_DIR}/

    cp -f ${CERTS_DIR}/* ${TMP_CA_DIR}/
    chown -R 0:0 ${TMP_CA_DIR}
    set_context ${APEX_CERTS} ${TMP_CA_DIR}

    CERTS_NUM="$(ls -1 ${TMP_CA_DIR} | wc -l)"
    if [ "$CERTS_NUM" -gt 10 ]; then
        bind_target() {
            target="$1"
            pid="$2"
            nsenter --mount=/proc/${pid}/ns/mnt -- /bin/mount --bind ${TMP_CA_DIR} ${target}
        }

        # Bind init namespace trước để process mới có cơ hội kế thừa.
        bind_target ${APEX_CERTS} 1
        bind_target ${SYSTEM_CERTS} 1

        # Ở post-fs-data, zygote có thể chưa sẵn sàng. Retry nhiều lần ngắn.
        i=0
        while [ "$i" -lt 20 ]; do
            zygotes="$(pgrep zygote 2>/dev/null) $(pgrep zygote64 2>/dev/null)"
            if [ -n "$(echo "$zygotes" | tr -d ' ')" ]; then
                for pid in $zygotes; do
                    bind_target ${APEX_CERTS} ${pid}
                    bind_target ${SYSTEM_CERTS} ${pid}
                done
                break
            fi
            sleep 1
            i=$((i+1))
        done
    else
        echo "Cancelling replacing CA storage due to safety"
    fi
fi

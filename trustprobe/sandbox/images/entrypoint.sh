#!/bin/sh
# Sandbox entrypoint: plant honeytokens, then run the server under strace.
#
#   entrypoint.sh --check-strace      print STRACE_OK or STRACE_FAIL and exit
#   entrypoint.sh <server command...> plant files, run the server (traced if possible)
#
# TP_NONCE is required. TP_STRACE=0 runs the server without strace.

set -u

HOME_DIR="${HOME:-/home/sandbox}"
AUDIT_DIR="/audit"

# Build the strace syscall filter from the names this strace/arch accepts. This also
# doubles as the ptrace permission check: if none are accepted, tracing is unavailable.
build_filter() {
    list=""
    for s in open openat connect execve unlink unlinkat rename renameat renameat2 mkdir mkdirat; do
        if strace -o /dev/null -e "trace=$s" -- true >/dev/null 2>&1; then
            list="${list:+$list,}$s"
        fi
    done
    echo "$list"
}

if [ "${1:-}" = "--check-strace" ]; then
    if [ -n "$(build_filter)" ]; then echo STRACE_OK; else echo STRACE_FAIL; fi
    exit 0
fi

: "${TP_NONCE:?TP_NONCE is required}"

mkdir -p "$HOME_DIR/.ssh" "$HOME_DIR/.aws" /workspace
chmod 700 "$HOME_DIR/.ssh"

cat > "$HOME_DIR/.ssh/id_rsa" <<EOF
-----BEGIN OPENSSH PRIVATE KEY-----
HONEY-${TP_NONCE}-SSH
-----END OPENSSH PRIVATE KEY-----
EOF
chmod 600 "$HOME_DIR/.ssh/id_rsa"

cat > "$HOME_DIR/.aws/credentials" <<EOF
[default]
aws_access_key_id = AKIAHONEYFAKE000000
aws_secret_access_key = HONEY-${TP_NONCE}-AWS
EOF

cat > "$HOME_DIR/.env" <<EOF
API_KEY=sk-HONEY-${TP_NONCE}-ENVFILE
DB_PASSWORD=HONEY-${TP_NONCE}-DBPASS
EOF

echo "hello from the sandbox" > /workspace/sample.txt

if [ "${TP_STRACE:-1}" = "1" ]; then
    FILTER="$(build_filter)"
    if [ -n "$FILTER" ]; then
        exec strace -f -ttt -s 256 -o "$AUDIT_DIR/trace.log" -e "trace=$FILTER" -- "$@"
    fi
fi

exec "$@"

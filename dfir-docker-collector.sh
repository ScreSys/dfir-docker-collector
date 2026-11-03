#!/bin/bash
#
# DFIR Docker Collector
# Forensic collection of running/stopped/paused Docker containers (Docker Engine, GNU userland).
#
# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
#   Interactive:
#     sudo OUT_ROOT=/mnt/evidence ./dfir-docker-collector.sh
#   Non-interactive:
#     sudo ./dfir-docker-collector.sh --out /mnt/evidence --case-id IR-2026-042 --all --yes --archive
#     sudo ./dfir-docker-collector.sh --out /mnt/evidence --include web1,db1 --yes
#     sudo ./dfir-docker-collector.sh --out /mnt/evidence --exclude monitoring --yes
#
# Options:
#   --out DIR         evidence destination (same as OUT_ROOT)
#   --case-id ID      case/ticket number
#   --all             all containers
#   --include a,b     only these containers (names or IDs)
#   --exclude a,b     all except these
#   --yes, -y         no prompts (needs --out and a selection flag)
#   --allow-exec      allow docker exec fallback (traced in exec_window.log)
#   --dump-mem        dump suspicious memory regions (needs python3)
#   --archive         create <BASE>.tar.gz (+ .age if AGE_RECIPIENT is set)
#   --no-apps         skip the application log/config/web-content check (step 3d)
#   -h, --help        this help
#
# Environment (defaults in brackets):
#   OUT_ROOT  MIN_FREE_MB[2048]  SPACE_FLOOR_MB[512]  EVENTS_DAYS[14]  RECENT_DAYS[7]
#   MAX_RECOVER_MB[200]  MAX_UPPER_MB[2048]  MAX_HOSTLOG_MB[500]  TIMEOUT[120]  CP_TIMEOUT[900]
#   ACCESS_DAYS[30]  MAX_APP_MB[2048]  COLLECT_APPS[1]
#   ALLOW_EXEC[0]  DUMP_MEM[0]  ARCHIVE[0]  AGE_RECIPIENT  TRUSTED_PATH
#
# Note: if the file has Windows line endings (CRLF) run:
#   sed -i 's/\r$//' dfir-docker-collector-v.sh
#
# ---------------------------------------------------------------------------

set -u
umask 077

# deterministic sorting/messages; trusted PATH; drop dangerous loader variables inherited from the caller.
export LC_ALL=C
export PATH="${TRUSTED_PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT 2>/dev/null

SCRIPT_VERSION="1"
SCRIPT_PATH=$(readlink -f "$0" 2>/dev/null || echo "$0")

# --- Configuration -----------------------------------------
OUT_ROOT="${OUT_ROOT:-}"
MIN_FREE_MB="${MIN_FREE_MB:-2048}"
SPACE_FLOOR_MB="${SPACE_FLOOR_MB:-512}"     # skip heavy copies below this free space
EVENTS_DAYS="${EVENTS_DAYS:-14}"
RECENT_DAYS="${RECENT_DAYS:-7}"
MAX_RECOVER_MB="${MAX_RECOVER_MB:-200}"     # cap per file recovered from /proc
MAX_UPPER_MB="${MAX_UPPER_MB:-2048}"        # cap for the UpperDir archive
MAX_HOSTLOG_MB="${MAX_HOSTLOG_MB:-500}"     # cap for raw host log copies
ACCESS_DAYS="${ACCESS_DAYS:-30}"            # days of sshd/sudo/cron/login journal to export
MAX_APP_MB="${MAX_APP_MB:-2048}"            # per-container cap for application logs/config/web content
COLLECT_APPS="${COLLECT_APPS:-1}"           # 0 = skip the application check (same as --no-apps)
TIMEOUT="${TIMEOUT:-120}"                   # seconds for find/nsenter
CP_TIMEOUT="${CP_TIMEOUT:-900}"             # seconds for each docker cp
ALLOW_EXEC="${ALLOW_EXEC:-0}"
DUMP_MEM="${DUMP_MEM:-0}"
ARCHIVE="${ARCHIVE:-0}"
AGE_RECIPIENT="${AGE_RECIPIENT:-}"

OPT_ALL=0; OPT_INCLUDE=""; OPT_EXCLUDE=""; ASSUME_YES=0; CASE_ID=""

usage() { sed -n '/^# Usage/,/^# Note/p' "$SCRIPT_PATH" | sed '$d' | sed 's/^# \{0,1\}//'; }

need_val() { [ "$2" -ge 2 ] || { echo "ERROR: option $1 needs a value" >&2; exit 2; }; }

while [ $# -gt 0 ]; do
    case "$1" in
        --out)        need_val "$1" $#; OUT_ROOT="$2"; shift ;;
        --case-id)    need_val "$1" $#; CASE_ID="$2"; shift ;;
        --include)    need_val "$1" $#; OPT_INCLUDE="$2"; shift ;;
        --exclude)    need_val "$1" $#; OPT_EXCLUDE="$2"; shift ;;
        --all)        OPT_ALL=1 ;;
        --yes|-y)     ASSUME_YES=1 ;;
        --allow-exec) ALLOW_EXEC=1 ;;
        --dump-mem)   DUMP_MEM=1 ;;
        --archive)    ARCHIVE=1 ;;
        --no-apps)    COLLECT_APPS=0 ;;
        -h|--help)    usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

# numeric sanity check of every tunable (they are used in arithmetic and as find/timeout arguments).
for v in MIN_FREE_MB SPACE_FLOOR_MB EVENTS_DAYS RECENT_DAYS MAX_RECOVER_MB MAX_UPPER_MB MAX_HOSTLOG_MB ACCESS_DAYS MAX_APP_MB TIMEOUT CP_TIMEOUT; do
    [[ "${!v}" =~ ^[0-9]+$ ]] || { echo "ERROR: $v must be a number (got: '${!v}')" >&2; exit 2; }
done

OUT_ROOT_DEFAULTED=0
if [ -z "$OUT_ROOT" ]; then OUT_ROOT="/tmp"; OUT_ROOT_DEFAULTED=1; fi

# output paths are only DEFINED here; directories are created after the pre-checks.
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
BASE_DIR="$OUT_ROOT/dfir_containers_$TIMESTAMP"
LOGFILE="$BASE_DIR/collection.log"
ERRFILE="$BASE_DIR/collection_errors.log"
ERRDIR="$BASE_DIR/ERROR_LOG"
ACTIONS_LOG="$BASE_DIR/actions.log"
ALERTS="$BASE_DIR/triage_alerts.txt"
HOST_DIR="$BASE_DIR/HOST_ARTIFACTS"

# find -printf format for timelines (numeric owner, see README_formats.txt)
# mtime, ctime, uid, gid, type, size, path. Names containing newlines/tabs can still confuse parsers.
TL_FMT='%TY-%Tm-%TdT%TH:%TM:%TS\t%CY-%Cm-%CdT%CH:%CM:%CS\t%U\t%G\t%y\t%s\t/%P\n'

# Journal matches for "how did the attacker get onto the host": '+' means OR between different matches.
# (sshd, sudo, su, login, cron/atd, logind sessions, account management tools)
# OpenSSH >= 9.8 logs the per-connection process as "sshd-session", OpenSSH >= 10.0 the auth process as "sshd-auth":
# with only "sshd" the logins of recent distributions are missed.
JOURNAL_ACCESS_MATCHES=(
    _SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service + _SYSTEMD_UNIT=cron.service + _SYSTEMD_UNIT=crond.service
    + _SYSTEMD_UNIT=atd.service + _SYSTEMD_UNIT=systemd-logind.service
    + SYSLOG_IDENTIFIER=sshd + SYSLOG_IDENTIFIER=sshd-session + SYSLOG_IDENTIFIER=sshd-auth + SYSLOG_IDENTIFIER=sudo + SYSLOG_IDENTIFIER=su + SYSLOG_IDENTIFIER=login
    + SYSLOG_IDENTIFIER=CRON + SYSLOG_IDENTIFIER=crond + SYSLOG_IDENTIFIER=pkexec + SYSLOG_IDENTIFIER=passwd
    + SYSLOG_IDENTIFIER=chpasswd + SYSLOG_IDENTIFIER=useradd + SYSLOG_IDENTIFIER=usermod + SYSLOG_IDENTIFIER=userdel
    + SYSLOG_IDENTIFIER=groupadd + _COMM=sudo + _COMM=su
)

# Well-known applications: "name|logs and config paths|content paths" (paths separated by spaces, inside the container).
# Logs/config are collected first for ALL apps, content (webroots, webapps) afterwards, all under MAX_APP_MB per container.
# Data directories (database files, indexes) are deliberately NOT listed: too large and rarely needed for triage.
# Secrets (jenkins secrets, gitlab-secrets.json, wp-config...) are not listed on purpose; add them if the case requires it.
APP_TABLE=(
    "nginx|/var/log/nginx /etc/nginx /usr/local/nginx/logs /usr/local/nginx/conf /usr/local/openresty/nginx/logs /usr/local/openresty/nginx/conf|/usr/share/nginx/html /usr/local/nginx/html"
    "apache|/var/log/apache2 /var/log/httpd /etc/apache2 /etc/httpd /usr/local/apache2/logs /usr/local/apache2/conf|/var/www /usr/local/apache2/htdocs"
    "php|/etc/php /usr/local/etc/php /usr/local/etc/php-fpm.d /var/log/php-fpm|"
    "tomcat|/usr/local/tomcat/logs /usr/local/tomcat/conf /opt/tomcat/logs /opt/tomcat/conf /var/log/tomcat /var/log/tomcat9 /var/log/tomcat10 /etc/tomcat9 /etc/tomcat10|/usr/local/tomcat/webapps /opt/tomcat/webapps"
    "wildfly-jboss|/opt/jboss/wildfly/standalone/log /opt/jboss/wildfly/standalone/configuration /opt/jboss/keycloak/standalone/log|/opt/jboss/wildfly/standalone/deployments"
    "keycloak|/opt/keycloak/data/log /opt/keycloak/conf|"
    "mysql-mariadb|/var/log/mysql /var/log/mariadb /etc/mysql /etc/my.cnf /etc/my.cnf.d|"
    "postgres|/var/log/postgresql /var/lib/postgresql/data/log /var/lib/postgresql/data/pg_log /var/lib/postgresql/data/postgresql.conf /var/lib/postgresql/data/pg_hba.conf /etc/postgresql|"
    "mssql|/var/opt/mssql/log /var/opt/mssql/mssql.conf|"
    "mongodb|/var/log/mongodb /etc/mongod.conf /etc/mongodb.conf|"
    "redis|/var/log/redis /etc/redis /usr/local/etc/redis|"
    "elasticsearch|/usr/share/elasticsearch/logs /usr/share/elasticsearch/config /var/log/elasticsearch /etc/elasticsearch|"
    "logstash|/usr/share/logstash/logs /usr/share/logstash/config /usr/share/logstash/pipeline /var/log/logstash|"
    "kafka-zookeeper|/opt/kafka/logs /opt/kafka/config /kafka/logs /var/log/kafka /var/log/zookeeper|"
    "rabbitmq|/var/log/rabbitmq /etc/rabbitmq|"
    "haproxy|/var/log/haproxy /usr/local/etc/haproxy /etc/haproxy|"
    "traefik|/var/log/traefik /etc/traefik /traefik.yml|"
    "caddy|/var/log/caddy /etc/caddy /config/caddy|"
    "jenkins|/var/jenkins_home/logs /var/jenkins_home/config.xml|"
    "gitlab|/var/log/gitlab|"
    "grafana|/var/log/grafana /etc/grafana|"
    "atlassian|/var/atlassian/application-data/jira/log /var/atlassian/application-data/confluence/logs|"
    "supervisor|/var/log/supervisor /etc/supervisor /etc/supervisord.conf|"
    "rsyslog|/etc/rsyslog.conf /etc/rsyslog.d|"
    "python-wsgi|/var/log/gunicorn /var/log/uwsgi /etc/uwsgi /etc/gunicorn|"
    "node-pm2|/root/.pm2/logs /home/node/.pm2/logs /usr/src/app/logs|"
    "generic-app-logs|/app/logs /app/log /opt/app/logs /srv/logs /logs /data/logs /var/log/app|"
)
declare -A APP_SEEN=()
declare -A VARLOG_COVERED=()    # /var/log/* app paths already inside the verified var_log.tar.gz -> size_kb
APP_TOTAL_KB=0
APP_CAP_HIT=0

# --- Utility functions ------------------------------
utc_now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# append to the error log with timestamp.
note()  { echo "[$(utc_now)] $*" >> "$ERRFILE"; }

# triage alert: printed, logged and saved in triage_alerts.txt.
alert() { echo "[$(utc_now)] ALERT: $*" | tee -a "$ALERTS"; }

# audit trail of every external action.
log_action() { [ -d "$BASE_DIR" ] && echo "[$(utc_now)] $*" >> "$ACTIONS_LOG"; return 0; }

# logged docker wrapper.
dk() { log_action "docker $*"; docker "$@" </dev/null; }

# logged docker wrapper with timeout: dkt <seconds> <docker args...>.
dkt() { local t="$1"; shift; log_action "docker $* (timeout ${t}s)"; timeout "${t}s" docker "$@" </dev/null; }

# ask VAR "prompt" "default" - honours --yes.
ask() {
    local __var="$1" __prompt="$2" __def="${3:-}" __ans=""
    if [ "$ASSUME_YES" -eq 1 ]; then printf -v "$__var" '%s' "$__def"; return 0; fi
    read -r -p "$__prompt" __ans
    printf -v "$__var" '%s' "${__ans:-$__def}"
}

# free space (MB) on OUT_ROOT.
free_mb() { df -Pm "$OUT_ROOT" 2>/dev/null | awk 'NR==2{print $4}'; }

# returns 1 if free space is below SPACE_FLOOR_MB.
space_ok() { [ "$(free_mb)" -ge "$SPACE_FLOOR_MB" ] 2>/dev/null; }

# sanitize a string to a safe file-name component (no slashes, no dots-only).
safe_name() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-64; }

# resolve names/IDs to FULL container IDs (containers only, never images/volumes).
# $2 = 1 (interactive prompts only): a number 1..N is the row of the container list shown to the operator.
normalize_ids() {
    local raw="$1" allow_index="${2:-0}" item full
    local -a items
    IFS=',' read -ra items <<< "$raw"
    for item in "${items[@]}"; do
        item=$(echo "$item" | tr -d '[:space:]')
        [ -z "$item" ] && continue
        case "$item" in -*) echo "WARNING: invalid name ignored -> $item" >&2; continue ;; esac
        if [ "$allow_index" -eq 1 ] && [[ "$item" =~ ^[0-9]+$ ]] \
           && [ "$((10#$item))" -ge 1 ] && [ "$((10#$item))" -le "${#ALL_ID_ARR[@]}" ]; then
            echo "${ALL_ID_ARR[$((10#$item - 1))]}"
            continue
        fi
        if full=$(dk container inspect --format '{{.Id}}' "$item" 2>/dev/null); then
            echo "$full"
        else
            echo "WARNING: container not found, ignored -> $item" >&2
        fi
    done
}

# all containers except the IDs listed in $1 (newline separated, may be empty).
select_all_except() {
    local id
    while read -r id; do
        [ -z "$id" ] && continue
        if [ -z "$1" ] || ! grep -qxF "$id" <<< "$1"; then printf '%s\n' "$id"; fi
    done <<< "$ALL_IDS"
}

# trace every docker exec (time window to exclude in the analysis).
exec_mark() { echo "[$(utc_now)] $*" >> "$BASE_DIR/exec_window.log"; }

# set the per-container context used by every collection function.
ctx_set() {
    local n s p
    CONTAINER="$1"
    IFS='|' read -r n s p <<< "$(dk container inspect --format '{{.Name}}|{{.State.Status}}|{{.State.Pid}}' "$CONTAINER" 2>/dev/null)"
    C_NAME="${n#/}"; C_STATE="${s:-unknown}"; C_PID="${p:-0}"
    [[ "$C_PID" =~ ^[0-9]+$ ]] || C_PID=0
    [ -n "$C_NAME" ] || C_NAME="unknown_${CONTAINER:0:12}"
    CONT_DIR="$BASE_DIR/containers/$C_NAME"
    CONT_DIR_ERROR="$CONT_DIR/ERROR_LOG"
    mkdir -p "$CONT_DIR" "$CONT_DIR_ERROR"
}

# copy a path out of the container. -a keeps UID/GID; timeout and free-space guards; no docker exec (a "copy" event is generated).
cp_from() {
    local src="$1" dst="$2"
    if ! space_ok; then note "[$C_NAME] free space below ${SPACE_FLOOR_MB} MB, NOT copied: $src"; return 1; fi
    dkt "$CP_TIMEOUT" cp -a "$CONTAINER:$src" "$dst" 2>>"$CONT_DIR_ERROR/$(basename "$dst")_stderr.txt"
    local rc=$?
    [ $rc -eq 124 ] && note "[$C_NAME] docker cp TIMEOUT (${CP_TIMEOUT}s): $src"
    return $rc
}

# run a command inside the container NETWORK namespace using HOST binaries.
# Fallback to docker exec ONLY with --allow-exec (every use is traced).
# usage/uso: netns_run <outfile> <command> [args...]
netns_run() {
    local out="$1"; shift
    local errf="$CONT_DIR_ERROR/$(basename "$out")_stderr.txt"
    local rc
    if [ "${C_PID:-0}" -gt 0 ] && command -v nsenter >/dev/null 2>&1 && command -v "$1" >/dev/null 2>&1; then
        log_action "nsenter -t $C_PID -n $*"
        timeout "${TIMEOUT}s" nsenter -t "$C_PID" -n "$@" > "$out" 2>>"$errf"
        rc=$?
    elif [ "$ALLOW_EXEC" -eq 1 ]; then
        exec_mark "BEGIN docker exec FALLBACK: $C_NAME -> $*"
        log_action "docker exec $CONTAINER $*"
        timeout "${TIMEOUT}s" docker exec "$CONTAINER" "$@" > "$out" 2>>"$errf"
        rc=$?
        exec_mark "END   docker exec FALLBACK (rc=$rc): $C_NAME -> $*"
    else
        note "[$C_NAME] SKIPPED '$*': nsenter/host tool missing and docker exec fallback not allowed (--allow-exec)"
        return 127
    fi
    [ $rc -ne 0 ] && note "[$C_NAME] '$*' failed or missing (rc=$rc)"
    return $rc
}

# find | sort -r > out, reporting timeouts (truncated output). usage: timed_find_to <out> <err> <find args...>
timed_find_to() {
    local out="$1" err="$2" rc; shift 2
    timeout "${TIMEOUT}s" find "$@" 2>>"$err" | sort -r > "$out"
    rc=${PIPESTATUS[0]}
    if [ "$rc" -eq 124 ]; then
        note "[$C_NAME] find TIMEOUT after ${TIMEOUT}s: output TRUNCATED -> $out"
        echo "# TRUNCATED: find timed out after ${TIMEOUT}s" >> "$out"
    fi
    return 0
}

# copy a host path with a size cap. usage: copy_capped <src> <dstdir>
copy_capped() {
    local src="$1" dstdir="$2" sz
    [ -e "$src" ] || return 0
    sz=$(du -sm "$src" 2>/dev/null | awk '{print $1}')
    if [ "${sz:-0}" -gt "$MAX_HOSTLOG_MB" ]; then
        note "host copy skipped, too large (${sz} MB > ${MAX_HOSTLOG_MB} MB): $src"
        return 1
    fi
    mkdir -p "$dstdir"
    cp -a --parents "$src" "$dstdir/" 2>>"$ERRDIR/host_copy_stderr.txt"
}

# run a host command if it exists, output to HOST_ARTIFACTS. usage: host_cmd <outfile> <cmd> [args...]
host_cmd() {
    local out="$1"; shift
    if command -v "$1" >/dev/null 2>&1; then
        "$@" > "$HOST_DIR/$out" 2>&1
    else
        note "host tool not found: $1"
    fi
}

# recover a file from /proc (deleted exe / fd, memfd) honoring the size cap; hash it immediately.
recover_file() {
    local src="$1" dst="$2" sz
    sz=$(stat -L -c %s "$src" 2>/dev/null || echo 0)
    mkdir -p "$(dirname "$dst")"
    if [ "$sz" -gt $((MAX_RECOVER_MB*1024*1024)) ]; then
        note "[$C_NAME] $src too large (${sz} B > ${MAX_RECOVER_MB} MB), NOT recovered"
        return 1
    fi
    if timeout 30s cp "$src" "$dst" 2>>"$CONT_DIR_ERROR/proc_recover_stderr.txt"; then
        { echo "src:    $src"; echo "target: $(readlink "$src" 2>/dev/null)"; echo "size:   $sz"; } > "$dst.origin.txt"
        sha256sum "$dst" >> "$CONT_DIR/proc_recovered/recovered_sha256_at_collection.txt" 2>/dev/null
    else
        note "[$C_NAME] cp failed: $src"
    fi
}

# OPTIONAL (--dump-mem): dump rwx and anonymous/memfd executable regions of a process via /proc/<PID>/mem (read-only, no ptrace attach).
dump_suspicious_regions() {
    local P="$1" D="$CONT_DIR/proc_recovered/pid${1}_memregions"
    command -v python3 >/dev/null 2>&1 || { note "[$C_NAME] python3 missing: --dump-mem skipped"; return 0; }
    mkdir -p "$D"
    python3 - "$P" "$D" "$MAX_RECOVER_MB" 2>>"$CONT_DIR_ERROR/memdump_stderr.txt" <<'PY'
import sys
pid, outdir, cap_mb = sys.argv[1], sys.argv[2], int(sys.argv[3])
cap, total = cap_mb * 1024 * 1024, 0
try:
    maps = open(f"/proc/{pid}/maps").read().splitlines()
    mem = open(f"/proc/{pid}/mem", "rb", 0)
except Exception as e:
    print(f"pid {pid}: {e}", file=sys.stderr)
    sys.exit(0)
index = open(f"{outdir}/index.txt", "w")
for line in maps:
    parts = line.split(None, 5)
    if len(parts) < 5:
        continue
    rng, perms = parts[0], parts[1]
    path = parts[5] if len(parts) > 5 else ""
    exec_anon = "x" in perms and (path == "" or "memfd:" in path or "(deleted)" in path)
    if not ("rwx" in perms or exec_anon):
        continue
    start, end = (int(x, 16) for x in rng.split("-"))
    size = end - start
    if total + size > cap:
        index.write(f"SKIPPED (cap) {line}\n")
        continue
    try:
        mem.seek(start)
        data = mem.read(size)
    except Exception as e:
        index.write(f"UNREADABLE {line} ({e})\n")
        continue
    name = f"{start:x}-{end:x}_{perms}.bin"
    with open(f"{outdir}/{name}", "wb") as fh:
        fh.write(data)
    total += size
    index.write(f"{name}\t{line}\n")
index.close()
PY
}

# build the host-PID list of the container with two independent methods:
# 1) docker top (cgroup)  2) /proc scan for identical PID namespace.
# pids_mismatch.txt: col 1 = only in docker top, col 2 (tab) = only in namespace scan.
build_pid_list() {
    local pidns hostpidns d p
    dk top "$CONTAINER" -eo pid 2>/dev/null | tail -n +2 | tr -d ' ' | sort -u > "$CONT_DIR/pids_docker_top.txt"
    : > "$CONT_DIR/pids_ns_scan.txt"
    : > "$CONT_DIR/pids_mismatch.txt"
    pidns=$(readlink "/proc/$C_PID/ns/pid" 2>/dev/null)
    hostpidns=$(readlink /proc/1/ns/pid 2>/dev/null)
    if [ -n "$pidns" ] && [ "$pidns" != "$hostpidns" ]; then
        for d in /proc/[0-9]*; do
            p=${d#/proc/}
            [ "$(readlink "$d/ns/pid" 2>/dev/null)" = "$pidns" ] && echo "$p"
        done | sort -u > "$CONT_DIR/pids_ns_scan.txt"
        comm -3 "$CONT_DIR/pids_docker_top.txt" "$CONT_DIR/pids_ns_scan.txt" > "$CONT_DIR/pids_mismatch.txt"
        [ -s "$CONT_DIR/pids_mismatch.txt" ] && alert "[$C_NAME] PID mismatch docker-top vs namespace scan (hidden/escaped processes?) -> $CONT_DIR/pids_mismatch.txt"
    else
        note "[$C_NAME] PID namespace equals host's (--pid=host?) or unreadable: namespace scan skipped"
    fi
    sort -u "$CONT_DIR/pids_docker_top.txt" "$CONT_DIR/pids_ns_scan.txt" | sed '/^$/d' > "$CONT_DIR/pids_all.txt"
}

# per-process /proc collection (host PID).
collect_proc_pid() {
    local P="$1" D="$CONT_DIR/proc/$1" e="$CONT_DIR_ERROR/proc_${1}_stderr.txt"
    local f t exe_link sha ppid uid capeff seccomp nnp cmd
    if [ ! -d "/proc/$P" ]; then
        note "[$C_NAME] PID $P exited during collection"
        return 1
    fi
    mkdir -p "$D"

    # text files "as is".
    for f in status stat statm io limits cgroup mounts mountinfo maps smaps_rollup comm \
             oom_score_adj loginuid sessionid uid_map gid_map attr/current wchan syscall; do
        cat "/proc/$P/$f" > "$D/$(echo "$f" | tr / _).txt" 2>>"$e"
    done

    # symlinks: exe (shows "(deleted)"/memfd), cwd, root (chroot).
    {
        echo "exe:  $(readlink "/proc/$P/exe" 2>&1)"
        echo "cwd:  $(readlink "/proc/$P/cwd" 2>&1)"
        echo "root: $(readlink "/proc/$P/root" 2>&1)"
    } > "$D/links.txt"

    # 2>> comes FIRST so the error of a failing "<" open lands in the stderr file, not on the console.
    tr '\0' '\n' 2>>"$e" < "/proc/$P/cmdline" > "$D/cmdline.txt"
    tr '\0' '\n' 2>>"$e" < "/proc/$P/environ" > "$D/environ.txt"     # may contain secrets
    ls -l "/proc/$P/fd"               > "$D/fd.txt"      2>>"$e"
    grep -H '' "/proc/$P"/fdinfo/*    > "$D/fdinfo.txt"  2>>"$e"
    ls -l "/proc/$P/ns"               > "$D/ns.txt"      2>>"$e"
    grep -H '' "/proc/$P"/task/*/comm > "$D/threads_comm.txt" 2>>"$e"

    # triage line.
    exe_link=$(readlink "/proc/$P/exe" 2>/dev/null)
    sha=$(sha256sum "/proc/$P/exe" 2>/dev/null | awk '{print $1}')
    ppid=$(awk '/^PPid:/{print $2}'       "/proc/$P/status" 2>/dev/null)
    uid=$(awk '/^Uid:/{print $2}'         "/proc/$P/status" 2>/dev/null)
    capeff=$(awk '/^CapEff:/{print $2}'   "/proc/$P/status" 2>/dev/null)
    seccomp=$(awk '/^Seccomp:/{print $2}' "/proc/$P/status" 2>/dev/null)
    nnp=$(awk '/^NoNewPrivs:/{print $2}'  "/proc/$P/status" 2>/dev/null)
    # tabs/newlines/NULs replaced by spaces so the TSV cannot be broken by a hostile cmdline.
    cmd=$(tr '\0\t\n\r' '    ' 2>/dev/null < "/proc/$P/cmdline")
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$P" "${ppid:-?}" "${uid:-?}" "${capeff:-?}" \
        "${seccomp:-?}" "${nnp:-?}" "${exe_link:-N/A}" "${sha:-N/A}" "$cmd" >> "$CONT_DIR/proc_summary.tsv"

    # recover deleted / memfd executable (fileless malware).
    case "$exe_link" in
        *"(deleted)"*)
            alert "[$C_NAME] PID $P runs a deleted/memfd executable: $exe_link"
            recover_file "/proc/$P/exe" "$CONT_DIR/proc_recovered/pid${P}_exe" ;;
    esac

    # recover open-but-deleted files (payloads, removed logs, memfd).
    for f in "/proc/$P"/fd/*; do
        [ -e "$f" ] || continue
        t=$(readlink "$f" 2>/dev/null)
        case "$t" in
            /*"(deleted)") recover_file "$f" "$CONT_DIR/proc_recovered/pid${P}_fd$(basename "$f")" ;;
        esac
    done

    [ "$DUMP_MEM" -eq 1 ] && dump_suspicious_regions "$P"
    return 0
}

# Quiet variant of cp_from for OPTIONAL paths: "not found" is a normal answer, not an error.
# Returns 0 = copied, 1 = not found, 2 = other failure (stderr kept in ERROR_LOG).
cp_try() {
    local src="$1" dst="$2" errf rc
    if ! space_ok; then note "[$C_NAME] free space below ${SPACE_FLOOR_MB} MB, NOT copied: $src"; return 2; fi
    errf=$(mktemp "$CONT_DIR_ERROR/.cp_try.XXXXXX") || return 2
    dkt "$CP_TIMEOUT" cp -a "$CONTAINER:$src" "$dst" 2>"$errf"
    rc=$?
    if [ $rc -eq 0 ]; then rm -f "$errf"; return 0; fi
    if grep -qiE 'could not find the file|no such (file|container:path)|not found' "$errf"; then
        rm -f "$errf"; return 1
    fi
    [ $rc -eq 124 ] && note "[$C_NAME] docker cp TIMEOUT (${CP_TIMEOUT}s): $src"
    mv -f "$errf" "$CONT_DIR_ERROR/$(basename "$dst")_stderr.txt" 2>/dev/null
    return 2
}

# Container logs according to the log driver (host phase, reads DockerRootDir directly).
# usage: collect_container_logs <full id> <name> <dest dir> <DockerRootDir/containers/id>
collect_container_logs() {
    local cid="$1" cn="$2" cdir="$3" src="$4" drv cfg f
    IFS='|' read -r drv cfg <<< "$(dk container inspect --format '{{.HostConfig.LogConfig.Type}}|{{json .HostConfig.LogConfig.Config}}' "$cid" 2>/dev/null)"
    drv="${drv:-unknown}"
    { echo "driver=$drv"; echo "options=${cfg:-null}"; } > "$cdir/log_driver.txt"

    case "$drv" in
        json-file|local) ;;
        journald)
            if command -v journalctl >/dev/null 2>&1; then
                journalctl CONTAINER_ID_FULL="$cid" --since "${EVENTS_DAYS} days ago" -o export \
                    > "$cdir/journald_container_logs.export" 2>>"$ERRDIR/journal_stderr.txt"
                journalctl CONTAINER_ID_FULL="$cid" --since "${EVENTS_DAYS} days ago" -o short-iso --no-pager \
                    > "$cdir/journald_container_logs.txt" 2>>"$ERRDIR/journal_stderr.txt"
            else
                alert "[$cn] log driver is journald but journalctl is not available on this host"
            fi ;;
        none) alert "[$cn] log driver is 'none': this container has NO logs" ;;
        *)    alert "[$cn] log driver '$drv' ships logs OFF this host (options: ${cfg:-null}): collect them from the remote destination" ;;
    esac
    case "$cfg" in *max-size*|*max-file*) note "[$cn] log rotation configured (${cfg}): older log history may be gone" ;; esac

    if [ -d "$src" ]; then
        # json-file logs (also rotated/compressed) + container config files
        for f in "$src"/*.log* "$src"/config.v2.json "$src"/hostconfig.json \
                 "$src"/hostname "$src"/hosts "$src"/resolv.conf; do
            [ -e "$f" ] && cp -a "$f" "$cdir/" 2>>"$ERRDIR/copy_container_files_stderr.txt"
        done
        # 'local' driver, and the dual-logging cache that Docker keeps for remote drivers
        if [ -d "$src/local-logs" ]; then
            cp -a "$src/local-logs" "$cdir/" 2>>"$ERRDIR/copy_container_files_stderr.txt"
        elif [ "$drv" = "local" ]; then
            note "[$cn] log driver is 'local' but $src/local-logs does not exist"
        fi
        if [ "$drv" = "json-file" ] && ! ls "$src"/*.log* >/dev/null 2>&1; then
            note "[$cn] log driver is json-file but no *.log* file exists in $src (logs removed or truncated?)"
        fi
    else
        note "[$cn] $src not found (non-standard root dir?)"
    fi
}

# Step 3b helper, run on the verified plaintext var_log copy before it is removed: record which /var/log/* paths of
# APP_TABLE it really contains, so collect_apps does not copy them twice. A path is covered only if it resolves INSIDE
# the copy: a symlinked log folder (or a symlinked /var/log) points elsewhere and is still collected by collect_apps.
varlog_index_apps() {
    local entry name lcp content p real base
    local -a plist
    [ -d "$CONT_DIR/var_log" ] && [ ! -L "$CONT_DIR/var_log" ] || return 0
    base=$(readlink -f "$CONT_DIR/var_log")
    for entry in "${APP_TABLE[@]}"; do
        IFS='|' read -r name lcp content <<< "$entry"
        read -ra plist <<< "$lcp $content"
        for p in "${plist[@]}"; do
            case "$p" in /var/log/?*) ;; *) continue ;; esac
            [ -e "$CONT_DIR/var_log/${p#/var/log/}" ] && [ ! -L "$CONT_DIR/var_log/${p#/var/log/}" ] || continue
            real=$(readlink -f "$CONT_DIR/var_log/${p#/var/log/}")
            case "$real" in "$base"/*) ;; *) continue ;; esac
            VARLOG_COVERED[$p]=$(du -sk "$real" 2>/dev/null | awk '{print $1}')
            : "${VARLOG_COVERED[$p]:=0}"
        done
    done
}

# Step 3d (pass 1 = "logs_conf", pass 2 = "content"): look for well-known applications inside the container
# and copy their log/config folders (or web content) with docker cp. A missing path is silently ignored,
# a found path is listed in apps/apps_detected.tsv. Works with the containerd image store (no UpperDir needed).
collect_apps() {
    local pass="$1" adir="$CONT_DIR/apps" cap_kb=$((MAX_APP_MB*1024))
    local entry name lcp content paths p dst rc sz_kb status
    local -a plist
    mkdir -p "$adir"
    [ -s "$adir/apps_detected.tsv" ] || printf 'class\tapp\tpath\tstatus\tsize_kb\n' > "$adir/apps_detected.tsv"
    for entry in "${APP_TABLE[@]}"; do
        IFS='|' read -r name lcp content <<< "$entry"
        if [ "$pass" = "logs_conf" ]; then paths="$lcp"; else paths="$content"; fi
        [ -n "$paths" ] || continue
        read -ra plist <<< "$paths"
        for p in "${plist[@]}"; do
            # already collected in var_log.tar.gz (step 3b): recorded for detection, not copied again, not counted in the cap.
            if [ -n "${VARLOG_COVERED[$p]:-}" ]; then
                if [ -z "${APP_SEEN[$name]:-}" ]; then
                    APP_SEEN[$name]=1
                    echo "[$(utc_now)] [$C_NAME] application detected: $name ($p, already in var_log.tar.gz)"
                fi
                printf '%s\t%s\t%s\t%s\t%s\n' "$pass" "$name" "$p" "IN_VAR_LOG" "${VARLOG_COVERED[$p]}" >> "$adir/apps_detected.tsv"
                continue
            fi
            if [ "$APP_TOTAL_KB" -ge "$cap_kb" ]; then
                if [ "$APP_CAP_HIT" -eq 0 ]; then
                    note "[$C_NAME] application collection cap reached (${MAX_APP_MB} MB): remaining paths SKIPPED"
                    APP_CAP_HIT=1
                fi
                return 0
            fi
            mkdir -p "$adir/$name"
            dst="$adir/$name/$(printf '%s' "$p" | sed 's|^/||; s|/|_|g')"
            cp_try "$p" "$dst"; rc=$?
            case $rc in
                0)  sz_kb=$(du -sk "$dst" 2>/dev/null | awk '{print $1}'); sz_kb=${sz_kb:-0}
                    APP_TOTAL_KB=$((APP_TOTAL_KB + sz_kb)); status="COPIED"
                    if [ -z "${APP_SEEN[$name]:-}" ]; then
                        APP_SEEN[$name]=1
                        echo "[$(utc_now)] [$C_NAME] application detected: $name ($p)"
                    fi ;;
                1)  continue ;;
                *)  sz_kb=0; status="FAILED" ;;
            esac
            printf '%s\t%s\t%s\t%s\t%s\n' "$pass" "$name" "$p" "$status" "$sz_kb" >> "$adir/apps_detected.tsv"
        done
        rmdir "$adir/$name" 2>/dev/null    # only removes it if nothing was copied (it is empty)
    done
}

# Log-like files inside bind mounts / volumes (app logs written outside the image layers), copied from the HOST side.
# Only regular files (find -type f never follows symlinks), per-file cap MAX_RECOVER_MB, shared cap MAX_APP_MB.
collect_volume_logs() {
    local adir="$CONT_DIR/apps" vdir="$CONT_DIR/apps/volume_logs" cap_kb=$((MAX_APP_MB*1024))
    local n=0 mtype msrc mdst f sz cnt
    [ -s "$CONT_DIR/mounts.txt" ] || return 0
    mkdir -p "$adir"
    [ -s "$adir/apps_detected.tsv" ] || printf 'class\tapp\tpath\tstatus\tsize_kb\n' > "$adir/apps_detected.tsv"
    while IFS='|' read -r mtype msrc mdst _; do
        n=$((n+1))
        { [ "$mtype" = "bind" ] || [ "$mtype" = "volume" ]; } || continue
        [ -d "$msrc" ] || continue
        if [ "$mtype" = "bind" ]; then
            # host system directories are collected in the host phase (or are not application data)
            case "$msrc" in
                /|/proc*|/sys*|/dev*|/etc|/etc/*|/run|/run/*|/var/run|/var/run/*|/boot*|/usr|/usr/*|/bin|/bin/*|/sbin|/sbin/*|/lib*|/var/log|/var/lib/docker*)
                    note "[$C_NAME] mount $n source '$msrc' skipped for volume log collection"; continue ;;
            esac
        fi
        cnt=0
        while IFS= read -r -d '' f; do
            if [ "$APP_TOTAL_KB" -ge "$cap_kb" ]; then
                if [ "$APP_CAP_HIT" -eq 0 ]; then
                    note "[$C_NAME] application collection cap reached (${MAX_APP_MB} MB): remaining volume logs SKIPPED"
                    APP_CAP_HIT=1
                fi
                break
            fi
            sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
            if [ "$sz" -gt $((MAX_RECOVER_MB*1024*1024)) ]; then
                note "[$C_NAME] volume log too large (${sz} B), skipped: $f"; continue
            fi
            mkdir -p "$vdir/mount${n}"
            if cp -a --parents "$f" "$vdir/mount${n}/" 2>>"$CONT_DIR_ERROR/volume_logs_stderr.txt"; then
                APP_TOTAL_KB=$((APP_TOTAL_KB + sz/1024 + 1)); cnt=$((cnt+1))
            fi
        done < <(timeout "${TIMEOUT}s" find "$msrc" -xdev -maxdepth 8 -type f \
                    \( -iname '*.log' -o -iname '*.log.*' -o -iname '*.err' -o -iname '*_log' -o -iname 'nohup.out' \) \
                    -print0 2>>"$CONT_DIR_ERROR/volume_logs_find_stderr.txt")
        if [ "$cnt" -gt 0 ]; then
            printf 'volume_logs\tmount%s\t%s -> %s (%s files)\tCOPIED\t-\n' "$n" "$msrc" "$mdst" "$cnt" >> "$adir/apps_detected.tsv"
            echo "[$(utc_now)] [$C_NAME] $cnt log file(s) copied from $mtype mount $msrc"
        fi
    done < "$CONT_DIR/mounts.txt"
}

# --- Pre-checks -------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run as root (needs /proc/<PID>, nsenter, /var/lib/docker)."
    exit 1
fi
if [ "${BASH_VERSINFO[0]}" -lt 4 ] || { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 4 ]; }; then
    echo "ERROR: bash >= 4.4 required (found ${BASH_VERSION})."
    exit 1
fi
# GNU userland needed (date -d, find -printf, du, stat -c, cp --parents).
if ! date -d '1 day ago' +%s >/dev/null 2>&1 || ! find /dev/null -printf '' >/dev/null 2>&1; then
    echo "ERROR: GNU date/find required (not BusyBox)."
    exit 1
fi
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found."; exit 1; }

if [ "$ASSUME_YES" -eq 0 ] && [ ! -t 0 ]; then
    echo "ERROR: stdin is not a terminal: use --yes with --out and --all/--include/--exclude."
    exit 1
fi
if [ "$ASSUME_YES" -eq 1 ] && [ -z "$OPT_INCLUDE" ] && [ -z "$OPT_EXCLUDE" ] && [ "$OPT_ALL" -eq 0 ]; then
    echo "ERROR: --yes requires a selection: --all, --include or --exclude."
    exit 1
fi

if [ "$OUT_ROOT_DEFAULTED" -eq 1 ]; then
    echo "WARNING: no --out/OUT_ROOT given: defaulting to /tmp (often tmpfs/RAM, same disk as the system under analysis)."
    if [ "$ASSUME_YES" -eq 1 ]; then echo "ERROR: with --yes an explicit --out is mandatory."; exit 1; fi
    ask ANS_TMP "Continue anyway? [y/N]: " "N"
    [[ "$ANS_TMP" =~ ^[Yy] ]] || { echo "Aborted."; exit 1; }
fi

mkdir -p "$OUT_ROOT" || { echo "ERROR: cannot create $OUT_ROOT"; exit 1; }
FS_TYPE=$(stat -f -c %T "$OUT_ROOT" 2>/dev/null)
[ "$FS_TYPE" = "tmpfs" ] && echo "WARNING: $OUT_ROOT is tmpfs (RAM): evidence is lost at reboot."

FREE_MB=$(free_mb)
if [ "${FREE_MB:-0}" -lt "$MIN_FREE_MB" ]; then
    echo "WARNING: free space on $OUT_ROOT = ${FREE_MB} MB (threshold: ${MIN_FREE_MB} MB)."
    if [ "$ASSUME_YES" -eq 1 ]; then echo "ERROR: not enough space in non-interactive mode."; exit 1; fi
    ask ANS_SPACE "Continue anyway? [y/N]: " "N"
    [[ "$ANS_SPACE" =~ ^[Yy] ]] || { echo "Aborted."; exit 1; }
fi

DOCKER_ROOT=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null)
if [ -n "$DOCKER_ROOT" ] && [ -d "$DOCKER_ROOT" ] \
   && [ "$(stat -c %d "$DOCKER_ROOT")" = "$(stat -c %d "$OUT_ROOT")" ]; then
    echo "WARNING: OUT_ROOT is on the same filesystem as $DOCKER_ROOT."
    echo "         Prefer an external/dedicated volume (--out /mnt/...)."
fi

# --- 0. Initial setup and case metadata ---
mkdir -p "$BASE_DIR" || { echo "ERROR: cannot create $BASE_DIR. Exiting."; exit 1; }
[ -w "$BASE_DIR" ] || { echo "ERROR: $BASE_DIR not writable. Exiting."; exit 1; }
mkdir -p "$ERRDIR" "$HOST_DIR" "$BASE_DIR/containers" || { echo "ERROR: subfolder creation failed."; exit 1; }
chmod 700 "$BASE_DIR"

# log everything to collection.log through tee; keep the original fds so we can close tee cleanly at the end.
exec 3>&1 4>&2
exec > >(tee -a "$LOGFILE") 2>&1
TEE_PID=$!

EXAMINER="${SUDO_USER:-$(logname 2>/dev/null || echo unknown)}"
echo "=== DFIR Docker Collector v${SCRIPT_VERSION} ==="
echo "Examiner: $EXAMINER (effective: $(whoami))"
echo "Host: $(hostname)"
echo "Date (UTC): $(date -u)"
echo "Output: $BASE_DIR"
echo "================================"

[ -n "$CASE_ID" ] || ask CASE_ID "Case/ticket number (optional, Enter to skip): " ""
{
    echo "Collector: dfir-docker-collector v${SCRIPT_VERSION}"
    echo "Script path: $SCRIPT_PATH"
    echo "Script SHA256: $(sha256sum "$SCRIPT_PATH" 2>/dev/null | awk '{print $1}')"
    echo "Case ID: ${CASE_ID:-N/A}"
    echo "Examiner: $EXAMINER (effective user: $(whoami))"
    echo "Hostname: $(hostname)"
    echo "Timestamp UTC: $(date -u)"
    echo "Timestamp local: $(date)"
    echo "Kernel: $(uname -a)"
    echo "Bash: $BASH_VERSION"
    echo "Docker client/server: $(docker version --format '{{.Client.Version}} / {{.Server.Version}}' 2>/dev/null)"
    echo "nsenter available: $(command -v nsenter >/dev/null 2>&1 && echo yes || echo no)"
    echo "Options: allow_exec=$ALLOW_EXEC dump_mem=$DUMP_MEM archive=$ARCHIVE events_days=$EVENTS_DAYS access_days=$ACCESS_DAYS recent_days=$RECENT_DAYS collect_apps=$COLLECT_APPS max_app_mb=$MAX_APP_MB"
} > "$BASE_DIR/case_metadata.txt"

cat > "$BASE_DIR/README_formats.txt" <<'EOF'
Timeline files (upperdir_timeline.tsv, mounts_timeline/*, recent_files_*.tsv), tab separated, sorted newest first:
  mtime  ctime  uid  gid  type(f/d/l/...)  size  /path
UID/GID are NUMERIC on purpose: the host passwd/group must not be used to resolve container IDs.
Integrity check:
  cd <this directory> && sha256sum -c SHA256SUMS.txt
  sha256sum -c SHA256SUMS.txt.sha256
Record the hash of SHA256SUMS.txt OUT OF BAND (ticket/case notes): it is printed at the end of the run.
Events generated by the collector itself: see actions.log (every docker command, UTC) and exec_window.log.
Container logs: containers/<name>/docker_container_files/ (log_driver.txt tells which driver is used and whether the logs live off-host).
Host login/access evidence: HOST_ARTIFACTS/journal_access.* , HOST_ARTIFACTS/raw_logs/ (wtmp, btmp, lastlog, ...), HOST_ARTIFACTS/decoded_*.txt
Application logs/config/web content: containers/<name>/apps/<app>/ ; apps_detected.tsv lists every path found (class app path status size_kb).
  status: COPIED (in apps/<app>/), IN_VAR_LOG (already in var_log.tar.gz, not copied twice), FAILED (see ERROR_LOG).
EOF

# one docker ps call: the IDs and the table shown to the operator come from the same snapshot (same order).
PS_TABLE=$(dk ps -a --no-trunc --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}')
ALL_IDS=$(cut -f1 <<< "$PS_TABLE" | sed '/^$/d')
if [ -z "$ALL_IDS" ]; then
    echo "No containers on this host. Exiting."
    exit 1
fi
mapfile -t ALL_ID_ARR <<< "$ALL_IDS"

# list every container (running AND stopped: both are evidence) before asking what to collect.
# The row number (#) can be used in the interactive prompts instead of names/IDs.
echo ""
echo "--- Containers on this host (${#ALL_ID_ARR[@]} total, $(awk -F'\t' '$4 ~ /^Up/' <<< "$PS_TABLE" | wc -l) running/paused) ---"
printf '%3s  %-12s  %-24s  %-30s  %-26s  %s\n' "#" "ID" "NAME" "IMAGE" "STATUS" "PORTS"
i=0
while IFS=$'\t' read -r id name image status ports; do
    [ -n "$id" ] || continue
    i=$((i+1))
    printf '%3s  %-12s  %-24.24s  %-30.30s  %-26.26s  %s\n' "$i" "${id:0:12}" "$name" "$image" "$status" "$ports"
done <<< "$PS_TABLE"
echo ""

# --- Container selection ---
TARGET_LIST=""
SELECTION_MODE=""

if [ -n "$OPT_INCLUDE" ]; then
    TARGET_LIST=$(normalize_ids "$OPT_INCLUDE")
    SELECTION_MODE="explicit list: ${OPT_INCLUDE}"
elif [ "$OPT_ALL" -eq 1 ] || [ -n "$OPT_EXCLUDE" ]; then
    EXCLUDE_IDS=""
    if [ -n "$OPT_EXCLUDE" ]; then
        EXCLUDE_IDS=$(normalize_ids "$OPT_EXCLUDE")
        # refuse to silently collect everything if none of the exclusions resolved (privacy/legal exclusions!).
        if [ -z "$EXCLUDE_IDS" ]; then echo "ERROR: none of the excluded containers was found; refusing to collect all."; exit 1; fi
        SELECTION_MODE="all except: ${OPT_EXCLUDE}"
    else
        SELECTION_MODE="all containers"
    fi
    TARGET_LIST=$(select_all_except "$EXCLUDE_IDS")
else
    ask ANS_ALL "Collect evidence from ALL containers? [Y/n]: " "Y"
    if [[ "$ANS_ALL" =~ ^[Yy] ]]; then
        ask ANS_EXCL "Exclude some? [y/N]: " "N"
        if [[ "$ANS_EXCL" =~ ^[Yy] ]]; then
            ask EXCLUDE_RAW "Numbers (#), names or IDs to EXCLUDE (comma separated): " ""
            EXCLUDE_IDS=$(normalize_ids "$EXCLUDE_RAW" 1)
            SELECTION_MODE="all except: ${EXCLUDE_RAW}"
            TARGET_LIST=$(select_all_except "$EXCLUDE_IDS")
        else
            TARGET_LIST="$ALL_IDS"
            SELECTION_MODE="all containers"
        fi
    else
        ask INCLUDE_RAW "Numbers (#), names or IDs to COLLECT (comma separated): " ""
        TARGET_LIST=$(normalize_ids "$INCLUDE_RAW" 1)
        SELECTION_MODE="explicit list: ${INCLUDE_RAW}"
    fi
fi

# drop empty lines and duplicates (e.g. "1,web1" pointing to the same container), keeping the order.
TARGET_LIST=$(echo "$TARGET_LIST" | sed '/^$/d' | awk '!seen[$0]++')
if [ -z "$TARGET_LIST" ]; then
    echo "ERROR: no valid container selected. Exiting."
    exit 1
fi

# summary and confirmation.
echo ""
echo "--- Containers selected for acquisition ---"
while read -r id; do
    printf "  %-14s %s\n" "${id:0:12}" "$(dk container inspect --format '{{.Name}} [{{.State.Status}}]' "$id" | sed 's/^\///')"
done <<< "$TARGET_LIST"
echo "Total: $(echo "$TARGET_LIST" | wc -l) containers"
echo ""

ask ANS_GO "Confirm and proceed? [Y/n]: " "Y"
[[ "$ANS_GO" =~ ^[Yy] ]] || { echo "Aborted by operator."; exit 0; }

# traceability in the case file.
{
    echo ""
    echo "Selection criterion: ${SELECTION_MODE}"
    echo "Acquired containers:"
    while read -r id; do
        echo "  - $id ($(dk container inspect --format '{{.Name}}' "$id" | sed 's/^\///'))"
    done <<< "$TARGET_LIST"
} >> "$BASE_DIR/case_metadata.txt"

# ---------------------------------------------------------------------------
# --- 1. HOST PHASE: before any per-container operation ---
# docker events/journal/audit are collected NOW so they do not contain what the collector itself
# generates later (docker top, docker cp, an optional exec all create events).
# ---------------------------------------------------------------------------
echo "[$(utc_now)] PHASE 1 - host artifacts..."

# event history with UNIX timestamps (no timezone ambiguity).
SINCE_EPOCH=$(date -d "${EVENTS_DAYS} days ago" +%s)
UNTIL_EPOCH=$(date +%s)
dk events --since "$SINCE_EPOCH" --until "$UNTIL_EPOCH" \
    > "$HOST_DIR/docker_events_${EVENTS_DAYS}d.txt" 2>>"$ERRDIR/docker_events_stderr.txt"

# the daemon keeps events in a small in-memory buffer: check whether the history is really complete.
EV_N=$(wc -l < "$HOST_DIR/docker_events_${EVENTS_DAYS}d.txt")
EV_FIRST=$(head -n1 "$HOST_DIR/docker_events_${EVENTS_DAYS}d.txt" | cut -d' ' -f1)
EV_FIRST_EPOCH=$(date -d "$EV_FIRST" +%s 2>/dev/null || echo 0)
echo "docker events captured: ${EV_N}; oldest: ${EV_FIRST:-none}; requested since: $(date -u -d "@$SINCE_EPOCH" +%FT%TZ)" | tee "$HOST_DIR/docker_events_coverage.txt"
if [ "${EV_N:-0}" -eq 0 ] || [ "$EV_FIRST_EPOCH" -gt $((SINCE_EPOCH + 86400)) ]; then
    note "docker events history is probably TRUNCATED (oldest event is much newer than requested window): do not assume completeness"
fi

dk info                > "$HOST_DIR/docker_info.txt"     2>&1
dk info --format '{{.LoggingDriver}}' > "$HOST_DIR/docker_default_log_driver.txt" 2>&1
dk version             > "$HOST_DIR/docker_version.txt"  2>&1
dk network ls          > "$HOST_DIR/docker_networks.txt" 2>&1
dk volume ls           > "$HOST_DIR/docker_volumes.txt"  2>&1
dk images --digests    > "$HOST_DIR/docker_images.txt"   2>&1
dk ps -a --no-trunc    > "$HOST_DIR/docker_ps_all.txt"   2>&1

# volatile host state first (network, processes), slow collections last.
host_cmd host_iptables.txt      iptables -L -n -v
host_cmd host_iptables_nat.txt  iptables -t nat -L -n -v
host_cmd host_ip6tables.txt     ip6tables -L -n -v
host_cmd host_nft_ruleset.txt   nft list ruleset
host_cmd host_ip_addr.txt       ip addr
host_cmd host_ip_route.txt      ip route
host_cmd host_ss.txt            ss -tulpan
host_cmd host_ps_forest.txt     ps -eo pid,ppid,user,lstart,etime,args --forest
host_cmd host_lsmod.txt         lsmod
host_cmd host_last.txt          last -Faiw
host_cmd host_who.txt           who -a

# time sync (essential to interpret every timeline).
host_cmd host_timedatectl.txt   timedatectl status
host_cmd host_chrony.txt        chronyc tracking
host_cmd host_ntpq.txt          ntpq -p

# who can control Docker is root-equivalent; socket permissions.
host_cmd host_docker_group.txt  getent group docker
host_cmd host_sockets_perm.txt  ls -lnd /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock
host_cmd host_systemd_docker.txt systemctl cat docker.service containerd.service docker.socket

# host kernel state shared with containers (rootkits, escape vectors).
mkdir -p "$HOST_DIR/proc_host"
for f in version cmdline uptime loadavg modules mounts filesystems \
         sys/kernel/tainted sys/kernel/core_pattern sys/kernel/modprobe sys/kernel/osrelease \
         sys/kernel/randomize_va_space sys/kernel/kptr_restrict sys/kernel/yama/ptrace_scope \
         sys/kernel/unprivileged_bpf_disabled sys/kernel/modules_disabled \
         sys/user/max_user_namespaces sys/net/ipv4/ip_forward sys/fs/binfmt_misc/status; do
    cat "/proc/$f" > "$HOST_DIR/proc_host/$(echo "$f" | tr / _).txt" 2>>"$ERRDIR/proc_host_stderr.txt"
done
grep -H '' /proc/sys/fs/binfmt_misc/* > "$HOST_DIR/proc_host/binfmt_misc_entries.txt" 2>>"$ERRDIR/proc_host_stderr.txt"
TAINT=$(cat /proc/sys/kernel/tainted 2>/dev/null || echo 0)
[ "$TAINT" != "0" ] && alert "host kernel is TAINTED (value $TAINT): check out-of-tree/unsigned modules"

# key host configuration files (kept with their original path).
for f in /etc/docker/daemon.json /etc/containerd/config.toml /etc/systemd/system/docker.service.d \
         /etc/ld.so.preload /etc/crontab /etc/cron.d /etc/ssh/sshd_config /root/.ssh/authorized_keys; do
    [ -e "$f" ] && cp -a --parents "$f" "$HOST_DIR/" 2>>"$ERRDIR/host_files_stderr.txt"
done

# kernel ring buffer (both monotonic and wall-clock).
host_cmd host_dmesg_raw.txt     dmesg
host_cmd host_dmesg_ctime.txt   dmesg -T

# daemon logs and audit (if present).
if command -v journalctl >/dev/null 2>&1; then
    journalctl -u docker -u containerd --since "${EVENTS_DAYS} days ago" -o export \
        > "$HOST_DIR/journal_docker_containerd.export" 2>>"$ERRDIR/journal_stderr.txt"
    journalctl -k --since "${EVENTS_DAYS} days ago" -o export \
        > "$HOST_DIR/journal_kernel.export" 2>>"$ERRDIR/journal_stderr.txt"
    # Access activity: sshd, sudo, su, login, cron/atd, logind sessions, account tools (export = evidence, txt = readable).
    # Hosts where these services log ONLY to the journal have no auth.log: this is where the logins are.
    journalctl --since "${ACCESS_DAYS} days ago" -o export "${JOURNAL_ACCESS_MATCHES[@]}" \
        > "$HOST_DIR/journal_access.export" 2>>"$ERRDIR/journal_stderr.txt"
    journalctl --since "${ACCESS_DAYS} days ago" -o short-iso --no-pager "${JOURNAL_ACCESS_MATCHES[@]}" \
        > "$HOST_DIR/journal_access.txt" 2>>"$ERRDIR/journal_stderr.txt"
    # Journal coverage: boots list, disk usage, persistent vs volatile, oldest entry vs requested window.
    journalctl --list-boots --no-pager > "$HOST_DIR/journal_boots.txt" 2>&1
    journalctl --disk-usage            > "$HOST_DIR/journal_disk_usage.txt" 2>&1
    if [ ! -d /var/log/journal ]; then
        alert "systemd journal is VOLATILE (/run/log/journal only): history is lost at every reboot"
    fi
    JR_OLDEST=$(journalctl --no-pager -o short-unix 2>/dev/null | head -n 3 | grep -m1 -oE '^[0-9]+')
    echo "journal oldest entry (epoch): ${JR_OLDEST:-unknown}; requested access window since: $(date -u -d "${ACCESS_DAYS} days ago" +%FT%TZ)" \
        | tee "$HOST_DIR/journal_coverage.txt"
    if [ -n "${JR_OLDEST:-}" ] && [ "$JR_OLDEST" -gt $(( $(date -d "${ACCESS_DAYS} days ago" +%s) + 86400 )) ]; then
        note "journal starts much later than the requested ${ACCESS_DAYS}-day access window (rotated/vacuumed?): access history is INCOMPLETE"
    fi
else
    note "journalctl not found: host journal not collected (non-systemd host?)"
fi
if command -v ausearch >/dev/null 2>&1; then
    ausearch -i -ts "$(date -d "${EVENTS_DAYS} days ago" '+%m/%d/%Y %H:%M:%S')" \
        > "$HOST_DIR/audit_recent.txt" 2>>"$ERRDIR/audit_stderr.txt"
fi
# raw logs (size-capped): the interpreted output above is not a substitute for the originals.
copy_capped /var/log/audit "$HOST_DIR/raw_logs"
for f in /var/log/auth.log /var/log/auth.log.1 /var/log/secure /var/log/secure-* /var/log/syslog /var/log/messages; do
    [ -e "$f" ] && copy_capped "$f" "$HOST_DIR/raw_logs"
done

# Binary login records: raw originals (evidence) + decoded text. utmp is the live "who is logged in" table.
for f in /var/log/wtmp* /var/log/btmp* /var/log/lastlog /var/log/faillog /run/utmp; do
    [ -f "$f" ] || continue
    copy_capped "$f" "$HOST_DIR/raw_logs" || true
    b=$(safe_name "$(basename "$f")")
    case "$(basename "$f")" in
        wtmp*) command -v last  >/dev/null 2>&1 && last  -Faiw -f "$f" > "$HOST_DIR/decoded_${b}.txt" 2>&1 ;;
        btmp*) command -v lastb >/dev/null 2>&1 && lastb -Faiw -f "$f" > "$HOST_DIR/decoded_${b}.txt" 2>&1 ;;
    esac
    case "$(basename "$f")" in
        wtmp*|btmp*|utmp) command -v utmpdump >/dev/null 2>&1 && utmpdump "$f" > "$HOST_DIR/decoded_${b}_utmpdump.txt" 2>&1 ;;
    esac
done
host_cmd host_lastlog.txt lastlog
# A cleared/missing wtmp or btmp is a classic anti-forensic step (it can also be a minimal host).
[ -s /var/log/wtmp ] || note "/var/log/wtmp is missing or empty: login history unavailable (log clearing or minimal host)"
[ -s /var/log/btmp ] || note "/var/log/btmp is missing or empty: failed-login history unavailable"

# container json logs + config from DockerRootDir (direct copy, no daemon involved).
echo "[$(utc_now)] PHASE 1b - container logs (log driver aware) and config of the selected containers..."
for CID in $TARGET_LIST; do
    CN=$(dk container inspect --format '{{.Name}}' "$CID" | sed 's/^\///')
    CDIR="$BASE_DIR/containers/$CN/docker_container_files"
    mkdir -p "$CDIR"
    collect_container_logs "$CID" "$CN" "$CDIR" "$DOCKER_ROOT/containers/$CID"
done

echo "[$(utc_now)] Host phase completed."

# ---------------------------------------------------------------------------
# --- 2. VOLATILE PHASE for ALL containers ---
# /proc and network state is a snapshot: collect it for every container BEFORE the slow static copies.
# processes of running AND paused/restarting containers (anything with a live PID).
# ---------------------------------------------------------------------------
echo "[$(utc_now)] PHASE 2 - volatile data (/proc, network)"
for CONTAINER_ID in $TARGET_LIST; do
    ctx_set "$CONTAINER_ID"
    if [ "$C_PID" -le 0 ]; then
        note "[$C_NAME] no live PID (state: $C_STATE): live data skipped"
        continue
    fi
    echo "[$(utc_now)] [$C_NAME] state: $C_STATE, host PID: $C_PID - live collection via nsenter and /proc/$C_PID"

    # docker top runs ps on the HOST (PIDs are host PIDs); it fails on paused containers (namespace scan still works).
    dk top "$CONTAINER" -eo pid,ppid,user,lstart,etime,args > "$CONT_DIR/ps_host_view.txt" 2>"$CONT_DIR_ERROR/ps_host_view_stderr.txt" \
        || note "[$C_NAME] docker top failed"
    dk top "$CONTAINER" > "$CONT_DIR/docker_top.txt" 2>"$CONT_DIR_ERROR/docker_top_stderr.txt"

    build_pid_list
    printf 'pid\tppid\tuid\tcapeff\tseccomp\tnonewprivs\texe\tsha256_exe\tcmdline\n' > "$CONT_DIR/proc_summary.tsv"
    while read -r -u 9 P; do
        [ -n "$P" ] && collect_proc_pid "$P"
    done 9< "$CONT_DIR/pids_all.txt"

    # /proc/<PID>/net: network tables of the container namespace (ss/netstat/arp/route equivalent, tool-free).
    mkdir -p "$CONT_DIR/proc_net"
    for f in dev route arp tcp tcp6 udp udp6 raw raw6 unix packet netlink if_inet6 sockstat snmp; do
        cat "/proc/$C_PID/net/$f" > "$CONT_DIR/proc_net/$f.txt" 2>>"$CONT_DIR_ERROR/proc_net_stderr.txt"
    done

    # container network namespace, HOST binaries (PIDs shown are host PIDs).
    netns_run "$CONT_DIR/ss.txt"            ss -tulpan
    netns_run "$CONT_DIR/network_ip.txt"    ip a
    netns_run "$CONT_DIR/network_arp.txt"   ip neigh
    netns_run "$CONT_DIR/network_route.txt" ip route
    netns_run "$CONT_DIR/lsof_net.txt"      lsof -i -P -n
done

# ---------------------------------------------------------------------------
# --- 3. STATIC PHASE per container ---
# ---------------------------------------------------------------------------
echo "[$(utc_now)] PHASE 3 - static data"

# files/dirs copied out of the container: "<container path>|<name inside the output folder>"
CP_LIST=(
    "/etc/passwd|passwd" "/etc/shadow|shadow" "/etc/group|group" "/etc/hosts|hosts.txt"
    "/etc/resolv.conf|resolv.conf.txt" "/etc/nsswitch.conf|nsswitch.conf.txt" "/etc/os-release|os-release.txt"
    "/etc/ld.so.preload|ld.so.preload" "/etc/ld.so.conf|ld.so.conf" "/etc/ld.so.conf.d|ld.so.conf.d"
    "/etc/profile|profile" "/etc/profile.d|profile.d" "/etc/environment|environment"
    "/etc/sudoers|sudoers" "/etc/sudoers.d|sudoers.d" "/etc/ssh/sshd_config|sshd_config"
    "/var/lib/dpkg/status|packages_dpkg_status.txt" "/lib/apk/db/installed|packages_apk_installed.txt"
    "/var/lib/rpm|packages_rpm_db" "/usr/lib/sysimage/rpm|packages_rpm_sysimage_db"
    "/var/spool/cron|cron_spool" "/etc/crontab|crontab" "/etc/crontabs|crontabs_alpine" "/etc/cron.d|cron_d"
    "/etc/cron.hourly|cron_hourly" "/etc/cron.daily|cron_daily" "/etc/cron.weekly|cron_weekly" "/etc/cron.monthly|cron_monthly"
    "/tmp|tmp" "/var/tmp|var_tmp" "/var/log|var_log"
)

# per-user artifacts (names relative to $HOME). Secrets (.aws, .kube, ...) are deliberately NOT included: add them if the case requires it.
USER_FILES=(.bash_history .ash_history .zsh_history .sh_history .python_history .mysql_history .psql_history
            .viminfo .lesshst .wget-hsts .ssh .local/share/Trash)

for CONTAINER_ID in $TARGET_LIST; do
    ctx_set "$CONTAINER_ID"
    echo "[$(utc_now)] [$C_NAME] static collection ($CONTAINER) state: $C_STATE"

    # 3a. Docker metadata (run from the host, no exec).
    dk container inspect "$CONTAINER" > "$CONT_DIR/docker_inspect.json" 2>>"$CONT_DIR_ERROR/docker_inspect_stderr.txt"
    # stdout+stderr of the container in ONE file (timestamps give the order); docker's own errors would also land here,
    # the raw json log copied in phase 1b is the authoritative source (it has a "stream" field).
    dk logs --timestamps "$CONTAINER" > "$CONT_DIR/docker_logs_combined.txt" 2>&1
    dk diff "$CONTAINER"   > "$CONT_DIR/docker_diff.txt"   2>>"$CONT_DIR_ERROR/docker_diff_stderr.txt"
    dk port "$CONTAINER"   > "$CONT_DIR/docker_port.txt"   2>>"$CONT_DIR_ERROR/docker_port_stderr.txt"
    dk stats "$CONTAINER" --no-stream > "$CONT_DIR/docker_stats.txt" 2>>"$CONT_DIR_ERROR/docker_stats_stderr.txt"

    # risk indicators (escape-relevant configuration).
    dk container inspect "$CONTAINER" --format \
'Privileged={{.HostConfig.Privileged}}{{"\n"}}CapAdd={{json .HostConfig.CapAdd}}{{"\n"}}CapDrop={{json .HostConfig.CapDrop}}{{"\n"}}PidMode={{.HostConfig.PidMode}}{{"\n"}}IpcMode={{.HostConfig.IpcMode}}{{"\n"}}NetworkMode={{.HostConfig.NetworkMode}}{{"\n"}}UsernsMode={{.HostConfig.UsernsMode}}{{"\n"}}SecurityOpt={{json .HostConfig.SecurityOpt}}{{"\n"}}Devices={{json .HostConfig.Devices}}{{"\n"}}ReadonlyRootfs={{.HostConfig.ReadonlyRootfs}}{{"\n"}}User={{.Config.User}}{{"\n"}}' \
        > "$CONT_DIR/risk_flags.txt" 2>>"$CONT_DIR_ERROR/risk_flags_stderr.txt"
    dk container inspect "$CONTAINER" --format '{{range .Mounts}}{{.Type}}|{{.Source}}|{{.Destination}}|rw={{.RW}}{{"\n"}}{{end}}' \
        > "$CONT_DIR/mounts.txt" 2>>"$CONT_DIR_ERROR/mounts_stderr.txt"
    dk container inspect "$CONTAINER" 2>>"$CONT_DIR_ERROR/flag_sock_stderr.txt" \
        | grep -Ei 'docker\.sock|containerd\.sock|crio\.sock|podman\.sock' > "$CONT_DIR/flag_runtime_socket_mount.txt"
    [ -s "$CONT_DIR/flag_runtime_socket_mount.txt" ] && alert "[$C_NAME] container runtime socket referenced in config (full host control) -> flag_runtime_socket_mount.txt"
    grep -Eqi 'Privileged=true|PidMode=host|IpcMode=host|NetworkMode=host|unconfined|"ALL"|SYS_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH|NET_ADMIN|NET_RAW' "$CONT_DIR/risk_flags.txt" \
        && alert "[$C_NAME] risky runtime configuration (see risk_flags.txt)"
    grep -Eq '^bind\|(/|/etc|/root|/proc|/sys|/var/run|/run|/var/lib/docker|/home)\|' "$CONT_DIR/mounts.txt" \
        && alert "[$C_NAME] sensitive host path bind-mounted (see mounts.txt)"

    # image history (reveals malicious build-time commands).
    IMAGE=$(dk container inspect --format '{{.Image}}' "$CONTAINER" 2>>"$ERRFILE")
    if [ -n "$IMAGE" ]; then
        dk history --no-trunc "$IMAGE" > "$CONT_DIR/image_history.txt" 2>>"$CONT_DIR_ERROR/image_history_stderr.txt"
    fi

    # UpperDir timeline + archive (the writable layer = what changed since the image).
    UPPER=$(dk container inspect --format '{{.GraphDriver.Data.UpperDir}}' "$CONTAINER" 2>>"$CONT_DIR_ERROR/upperdir_stderr.txt")
    if [ -n "$UPPER" ] && [ -d "$UPPER" ]; then
        timed_find_to "$CONT_DIR/upperdir_timeline.tsv" "$CONT_DIR_ERROR/upperdir_find_stderr.txt" "$UPPER" -xdev -printf "$TL_FMT"
        UP_MB=$(du -sxm "$UPPER" 2>/dev/null | awk '{print $1}')
        if [ "${UP_MB:-0}" -le "$MAX_UPPER_MB" ] && space_ok; then
            # --atime-preserve=system uses O_NOATIME so reading does not alter atime.
            tar --numeric-owner --xattrs --acls --one-file-system --atime-preserve=system \
                -C "$UPPER" -cf - . 2>>"$CONT_DIR_ERROR/upperdir_tar_stderr.txt" \
                | gzip -1 > "$CONT_DIR/upperdir.tar.gz"
            TAR_RC=${PIPESTATUS[0]}
            [ "$TAR_RC" -gt 1 ] && note "[$C_NAME] upperdir tar reported errors (rc=$TAR_RC), see ERROR_LOG/upperdir_tar_stderr.txt"
        else
            note "[$C_NAME] UpperDir archive SKIPPED (size ${UP_MB:-?} MB > ${MAX_UPPER_MB} MB cap, or low disk space)"
        fi
    else
        note "[$C_NAME] UpperDir not available (containerd image store / snapshotter?)"
        echo "N/A - containerd snapshotter or non overlay2-compatible storage driver" > "$CONT_DIR/upperdir_timeline.tsv"
    fi

    # volumes / bind mounts live OUTSIDE the UpperDir (webshells and app data are often there): recent-files timeline.
    mkdir -p "$CONT_DIR/mounts_timeline"
    idx=0
    while IFS='|' read -r mtype msrc _; do
        idx=$((idx+1))
        { [ "$mtype" = "bind" ] || [ "$mtype" = "volume" ]; } || continue
        case "$msrc" in ""|/|/proc*|/sys*|/dev*) note "[$C_NAME] mount $idx source '$msrc' skipped"; continue ;; esac
        [ -d "$msrc" ] || continue    # files such as sockets are already flagged
        echo "mount${idx}|${mtype}|${msrc}" >> "$CONT_DIR/mounts_timeline/index.txt"
        timed_find_to "$CONT_DIR/mounts_timeline/mount${idx}_recent_${RECENT_DAYS}d.tsv" "$CONT_DIR_ERROR/mount${idx}_find_stderr.txt" \
            "$msrc" -xdev \( -mtime "-$RECENT_DAYS" -o -ctime "-$RECENT_DAYS" \) -printf "$TL_FMT"
    done < "$CONT_DIR/mounts.txt"

    # files modified in the last N days, from the host, on the container filesystem view (live PID needed).
    if [ "$C_PID" -gt 0 ]; then
        ROOTFS="/proc/$C_PID/root"
        if [ -d "$ROOTFS/etc" ]; then
            timed_find_to "$CONT_DIR/recent_files_modified_${RECENT_DAYS}_days.tsv" "$CONT_DIR_ERROR/recent_files_stderr.txt" \
                -H "$ROOTFS" -xdev \( -mtime "-$RECENT_DAYS" -o -ctime "-$RECENT_DAYS" \) -type f -printf "$TL_FMT"
        else
            note "[$C_NAME] $ROOTFS not accessible: recent files skipped"
        fi
        # /dev/shm is tmpfs (docker cp cannot read it): copy from the host view, skipping symlinks and oversized dirs.
        SHM="$ROOTFS/dev/shm"
        if [ -d "$SHM" ] && [ ! -L "$SHM" ]; then
            SHM_MB=$(du -sm "$SHM" 2>/dev/null | awk '{print $1}')
            if [ "${SHM_MB:-0}" -le "$MAX_RECOVER_MB" ]; then
                mkdir -p "$CONT_DIR/dev_shm"
                cp -a "$SHM/." "$CONT_DIR/dev_shm/" 2>>"$CONT_DIR_ERROR/dev_shm_stderr.txt"
            else
                note "[$C_NAME] /dev/shm too large (${SHM_MB} MB), skipped"
            fi
        fi
    else
        note "[$C_NAME] no live PID (state: $C_STATE): recent-files view and /dev/shm skipped"
    fi

    # 3b. copy artifacts out of the container (docker cp works on stopped containers too).
    VARLOG_COVERED=(); VARLOG_CP_RC=1
    for entry in "${CP_LIST[@]}"; do
        cp_from "${entry%%|*}" "$CONT_DIR/${entry##*|}"; CP_RC=$?
        [ "${entry%%|*}" = "/var/log" ] && VARLOG_CP_RC=$CP_RC
    done

    # compress var_log and remove the plaintext copy ONLY if the archive was written AND verified.
    if [ -d "$CONT_DIR/var_log" ]; then
        if tar --numeric-owner -czf "$CONT_DIR/var_log.tar.gz" -C "$CONT_DIR" var_log 2>>"$CONT_DIR_ERROR/var_log_tar_stderr.txt" \
           && tar -tzf "$CONT_DIR/var_log.tar.gz" >/dev/null 2>>"$CONT_DIR_ERROR/var_log_tar_stderr.txt"; then
            # app log folders inside a COMPLETE copy are not copied again by step 3d (a failed/timed-out copy may be partial).
            [ "$VARLOG_CP_RC" -eq 0 ] && varlog_index_apps
            rm -rf "$CONT_DIR/var_log"
        else
            note "[$C_NAME] var_log compression/verification FAILED: plaintext copy KEPT"
            rm -f "$CONT_DIR/var_log.tar.gz"
        fi
    fi

    # 3c. user artifacts. /etc/passwd comes from the (possibly compromised) container: it is UNTRUSTED input.
    #     Output names are built only from the numeric uid + a sanitized name, never from raw passwd fields.
    if [ -f "$CONT_DIR/passwd" ]; then
        declare -A SEEN_HOME=()
        mkdir -p "$CONT_DIR/users_data"
        while IFS=: read -r user _ uid _ _ home _; do
            [[ "$uid" =~ ^[0-9]+$ ]] || uid="x"
            [[ "$home" == /* ]] && [ "$home" != "/" ] || continue
            [ -n "${SEEN_HOME[$home]:-}" ] && continue
            SEEN_HOME[$home]=1
            udir="$CONT_DIR/users_data/uid${uid}_$(safe_name "$user")"
            mkdir -p "$udir"
            printf '%s\n' "$home" > "$udir/home_path.txt"
            for item in "${USER_FILES[@]}"; do
                cp_from "$home/$item" "$udir/${item//\//_}"
            done
        done < "$CONT_DIR/passwd"
        # /root is handled separately (often not defined properly in custom images).
        if [ -z "${SEEN_HOME[/root]:-}" ]; then
            udir="$CONT_DIR/users_data/uid0_root_fallback"
            mkdir -p "$udir"
            for item in "${USER_FILES[@]}"; do
                cp_from "/root/$item" "$udir/${item//\//_}"
            done
        fi
        unset SEEN_HOME
    fi

    # 3d. LAST CHECK: well-known applications. Logs/config of every detected app first, then log-like files found
    #     inside bind mounts/volumes, then web content; all of it under the shared per-container cap MAX_APP_MB.
    if [ "$COLLECT_APPS" -eq 1 ]; then
        APP_SEEN=(); APP_TOTAL_KB=0; APP_CAP_HIT=0
        collect_apps logs_conf
        collect_volume_logs
        collect_apps content
        [ -s "$CONT_DIR/apps/apps_detected.tsv" ] || note "[$C_NAME] no well-known application paths found"
    fi

    echo "[$(utc_now)] [$C_NAME] completed"
done

# ---------------------------------------------------------------------------
# --- 4. Cleanup: ONLY empty files/dirs inside the tool's own ERROR_LOG folders ---
# anything else (empty .bash_history, empty .ssh dir copied from a container, ...) is information and stays.
# Explicit paths (not "-name ERROR_LOG") so a folder with that name inside the evidence is never touched.
# ---------------------------------------------------------------------------
echo "Cleaning empty error logs..."
for d in "$ERRDIR" "$BASE_DIR"/containers/*/ERROR_LOG; do
    [ -d "$d" ] && find "$d" -depth -empty \( -type f -o -type d \) -delete 2>/dev/null
done

# ---------------------------------------------------------------------------
# --- 5. Integrity: SHA256 manifest with RELATIVE paths ---
# ---------------------------------------------------------------------------
echo "Generating SHA256 manifest..."
(
    cd "$BASE_DIR" || exit 1
    find . -type f ! -name SHA256SUMS.txt ! -name SHA256SUMS.txt.sha256 ! -name collection.log -print0 \
        | sort -z | xargs -0 -r sha256sum > SHA256SUMS.txt
)

echo "=============================="
echo "[$(utc_now)] Acquisition completed. Data saved in: $BASE_DIR"
echo "Hash manifest:        $BASE_DIR/SHA256SUMS.txt"
echo "Error log: $ERRFILE"
echo "Docker actions log:   $ACTIONS_LOG"
[ -s "$ALERTS" ] && echo "TRIAGE ALERTS ($(wc -l < "$ALERTS")): $ALERTS"
[ -f "$BASE_DIR/exec_window.log" ] && echo "WARNING: docker exec fallback used. Time windows: $BASE_DIR/exec_window.log"
echo "=============================="

# close tee cleanly (restore the original fds, wait for the tee process) so collection.log is complete before hashing it.
exec 1>&3 2>&4 3>&- 4>&-
wait "$TEE_PID" 2>/dev/null || sleep 2

(
    cd "$BASE_DIR" || exit 1
    sha256sum ./collection.log >> SHA256SUMS.txt
    sha256sum SHA256SUMS.txt > SHA256SUMS.txt.sha256
)

MANIFEST_HASH=$(awk '{print $1}' "$BASE_DIR/SHA256SUMS.txt.sha256")
echo "SHA256 of SHA256SUMS.txt (record it OUT OF BAND in the ticket):"
echo "  $MANIFEST_HASH"
echo "Verify:  cd $BASE_DIR && sha256sum -c SHA256SUMS.txt"

# --- 6. Optional archive (+ age encryption) ---
if [ "$ARCHIVE" -eq 1 ]; then
    ARCH="$BASE_DIR.tar.gz"
    if tar --numeric-owner -C "$OUT_ROOT" -czf "$ARCH" "$(basename "$BASE_DIR")"; then
        sha256sum "$ARCH" > "$ARCH.sha256"
        echo "Archive: $ARCH (sha256: $(awk '{print $1}' "$ARCH.sha256"))"
        if [ -n "$AGE_RECIPIENT" ]; then
            if command -v age >/dev/null 2>&1 && age -r "$AGE_RECIPIENT" -o "$ARCH.age" "$ARCH"; then
                sha256sum "$ARCH.age" > "$ARCH.age.sha256"
                echo "Encrypted: $ARCH.age (sha256: $(awk '{print $1}' "$ARCH.age.sha256"))"
                echo "The plaintext folder and .tar.gz still exist: remove them securely after copying the .age file."
            else
                echo "WARNING: age missing or failed: archive NOT encrypted."
            fi
        else
            echo "NOTE: set AGE_RECIPIENT to encrypt (shadow, ssh keys and process environments are in clear text)."
        fi
    else
        echo "WARNING: archive creation failed."
    fi
fi
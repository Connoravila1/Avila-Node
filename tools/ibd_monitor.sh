#!/usr/bin/env bash
# ibd_monitor.sh — tail the sync event journal + process stats into a
# timestamped CSV log for the overnight flat-IBD run.
#
# Usage: tools/ibd_monitor.sh <datadir-net-dir> [pid] [log]
#   datadir-net-dir  e.g. data-flat/mainnet  (contains events.ndjson)
#   pid              avila-node process id (optional; auto-finds)
#   log              output file (default: <datadir>/ibd_monitor.log)
#
# Columns: iso_time, height, rss_mib, cpu_pct, memavail_mib,
#          temp_mc (x86_pkg_temp millideg), blk_gib, coinsdb_gib
# Plus a verbatim tail of notable events (audits, stalls, errors).

set -u
DIR="${1:?datadir-net-dir}"
PID="${2:-}"
LOG="${3:-$DIR/ibd_monitor.log}"
EVENTS="$DIR/events.ndjson"
INTERVAL="${IBD_MONITOR_INTERVAL:-60}"
MIN_MEM_MIB="${IBD_MONITOR_MIN_MEM_MIB:-1500}"

find_pid() {
    pgrep -f "avila-node run" | head -1 || true
}

echo "# ibd_monitor $(date -Is) dir=$DIR" >> "$LOG"
echo "# iso_time,height,rss_mib,cpu_pct,memavail_mib,temp_mc,blk_gib,coinsdb_gib" >> "$LOG"

last_height=0
while :; do
    [ -z "$PID" ] && PID=$(find_pid)
    if [ -n "$PID" ] && [ ! -d "/proc/$PID" ]; then
        echo "$(date -Is) PROCESS GONE pid=$PID" >> "$LOG"
        PID=""
    fi

    height=$(grep '"tip_advanced"' "$EVENTS" 2>/dev/null | tail -1 \
        | sed -n 's/.*"height":\([0-9]*\).*/\1/p')
    height=${height:-$last_height}

    rss=0; cpu=0
    if [ -n "$PID" ] && [ -d "/proc/$PID" ]; then
        rss=$(awk '/VmRSS/{print $2}' "/proc/$PID/status" 2>/dev/null || echo 0)
        rss=$((rss / 1024))
        cpu=$(ps -o %cpu= -p "$PID" 2>/dev/null | tr -d ' ' || echo 0)
    fi

    memavail=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)
    temp=$(cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null | sort -rn | head -1 || echo 0)

    blk_gib=$(du -sm "$DIR" 2>/dev/null | awk '{printf "%.1f", $1/1024}')
    coinsdb_gib=0
    [ -f "$DIR/coinsdb.redb" ] && \
        coinsdb_gib=$(du -sm "$DIR/coinsdb.redb" | awk '{printf "%.1f", $1/1024}')

    echo "$(date -Is),$height,$rss,$cpu,$memavail,$temp,$blk_gib,$coinsdb_gib" >> "$LOG"

    # Loud notables: audit failures and peer churn since last poll.
    tail -200 "$EVENTS" 2>/dev/null \
        | grep -E '"(self_audit_failed|peer_banned|store_error|panic)"' \
        | tail -5 >> "$LOG"

    if [ "$memavail" -lt "$MIN_MEM_MIB" ]; then
        echo "$(date -Is) MEMORY LOW ${memavail}MiB < ${MIN_MEM_MIB}MiB" >> "$LOG"
    fi
    last_height=$height
    sleep "$INTERVAL"
done

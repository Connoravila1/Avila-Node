#!/usr/bin/env bash
# guard_run.sh — memory-capped runner for heavy experiments on this laptop.
#
# Every job that can grow unboundedly (corpus builds, snapshot loads,
# window joins, node dumps) MUST run under this wrapper. It enforces a
# HARD kernel-level ceiling via a systemd user scope's MemoryMax — the
# kernel OOM-kills the job at the cap; the desktop survives. There is no
# polling gap: cgroup accounting is continuous.
#
# Usage:
#   guard_run.sh [--max MiB] [--reserve MiB] -- cmd [args...]
#
#   --max      hard memory ceiling for the job, MiB (default 8192)
#   --reserve  MiB that must remain free for the desktop besides the cap
#              (default 4096). The job REFUSES to start (exit 3) unless
#              MemAvailable >= max + reserve.
#
# Exit: the command's status (137/OOM-kill on cap breach), 3 on refusal.
# stderr reports the cgroup unit, its MemoryMax, and peak usage.

set -u
MAX_MIB=8192
RESERVE_MIB=4096
while [ $# -gt 0 ]; do
    case "$1" in
        --max) MAX_MIB="$2"; shift 2 ;;
        --reserve) RESERVE_MIB="$2"; shift 2 ;;
        --) shift; break ;;
        *) echo "guard_run: unknown flag $1" >&2; exit 2 ;;
    esac
done
[ $# -gt 0 ] || { echo "guard_run: no command" >&2; exit 2; }

avail=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)
need=$((MAX_MIB + RESERVE_MIB))
if [ "$avail" -lt "$need" ]; then
    echo "guard_run: REFUSING — MemAvailable=${avail}MiB < required=${need}MiB" \
         "(cap=${MAX_MIB}MiB + reserve=${RESERVE_MIB}MiB)" >&2
    exit 3
fi
# Host context at start: competing load is part of the measurement.
load0=$(cut -d' ' -f1-3 /proc/loadavg)
avail0=$avail
t0=$(date +%s)

# systemd-run in background so we can sample the scope cgroup while it lives.
tmp=$(mktemp)
systemd-run --user --scope \
    -p "MemoryMax=${MAX_MIB}M" -p "MemorySwapMax=0" -p "OOMPolicy=kill" \
    -- "$@" >"$tmp" 2>&1 &
runner=$!

# Wait for the unit name, then poll memory.current → peak.
unit=""
peak=0
slice="/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/app.slice"
while kill -0 "$runner" 2>/dev/null; do
    if [ -z "$unit" ]; then
        unit=$(grep -o 'run-[a-zA-Z0-9_-]*\.scope' "$tmp" 2>/dev/null | head -1)
    fi
    if [ -n "$unit" ] && [ -f "$slice/$unit/memory.current" ]; then
        cur=$(cat "$slice/$unit/memory.current" 2>/dev/null || echo 0)
        [ "$cur" -gt "$peak" ] && peak=$cur
    fi
    sleep 1
done
wait "$runner"; rc=$?

cat "$tmp" >&2
rm -f "$tmp"
# Fallback peak: memory.peak may still exist for a moment after exit.
if [ "$peak" -eq 0 ] && [ -n "$unit" ] && [ -f "$slice/$unit/memory.peak" ]; then
    peak=$(cat "$slice/$unit/memory.peak" 2>/dev/null || echo 0)
fi
# Host context at end + outer wall (includes receipt work the process
# reports before exiting).
load1=$(cut -d' ' -f1-3 /proc/loadavg)
avail1=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)
wall=$(( $(date +%s) - t0 ))
echo "guard_run: exit=$rc cap=${MAX_MIB}MiB peak=$((peak/1048576))MiB" \
     "wall_s=${wall} load=${load0}→${load1} memavail=${avail0}→${avail1}MiB" \
     "unit=${unit:-n/a}" >&2
exit "$rc"

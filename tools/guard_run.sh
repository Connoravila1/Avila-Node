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
# Mean clock across cores, kHz (cpufreq sysfs; empty if absent).
cpus_mhz() {
    local s=0 n=0 f
    for f in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq; do
        [ -r "$f" ] && { s=$((s + $(<"$f"))); n=$((n+1)); }
    done
    [ "$n" -gt 0 ] && echo "$((s/n))" || echo 0
}
mhz0=$(cpus_mhz)

# systemd-run in background so we can sample the scope cgroup while it lives.
tmp=$(mktemp)
systemd-run --user --scope \
    -p "MemoryMax=${MAX_MIB}M" -p "MemorySwapMax=0" -p "OOMPolicy=kill" \
    -- "$@" >"$tmp" 2>&1 &
runner=$!

# Wait for the unit name, then poll memory.current + cpu.stat + clocks.
unit=""
peak=0
mhz_min=0; mhz_max=0; mhz_sum=0; mhz_n=0
cpu_usec0=""
slice="/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/app.slice"
while kill -0 "$runner" 2>/dev/null; do
    if [ -z "$unit" ]; then
        unit=$(grep -o 'run-[a-zA-Z0-9_-]*\.scope' "$tmp" 2>/dev/null | head -1)
    fi
    if [ -n "$unit" ]; then
        if [ -f "$slice/$unit/memory.current" ]; then
            cur=$(cat "$slice/$unit/memory.current" 2>/dev/null || echo 0)
            [ "$cur" -gt "$peak" ] && peak=$cur
        fi
        if [ -f "$slice/$unit/cpu.stat" ]; then
            u=$(awk '/usage_usec/{print $2}' "$slice/$unit/cpu.stat" 2>/dev/null)
            [ -n "$u" ] && { [ -z "$cpu_usec0" ] && cpu_usec0=$u; cpu_last=$u; }
        fi
    fi
    m=$(cpus_mhz)
    if [ "$m" -gt 0 ]; then
        mhz_sum=$((mhz_sum + m)); mhz_n=$((mhz_n + 1))
        [ $mhz_min -eq 0 ] || [ "$m" -lt "$mhz_min" ] && mhz_min=$m
        [ "$m" -gt "$mhz_max" ] && mhz_max=$m
    fi
    sleep 1
done
wait "$runner"; rc=$?
cpu_usec1="${cpu_last:-}"

cat "$tmp" >&2
rm -f "$tmp"
# Fallback peak: memory.peak may still exist for a moment after exit.
if [ "$peak" -eq 0 ] && [ -n "$unit" ] && [ -f "$slice/$unit/memory.peak" ]; then
    peak=$(cat "$slice/$unit/memory.peak" 2>/dev/null || echo 0)
fi
# Host context at end + outer wall (includes receipt work the process
# reports before exiting) + CPU time and sustained-clock summary.
load1=$(cut -d' ' -f1-3 /proc/loadavg)
avail1=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)
wall=$(( $(date +%s) - t0 ))
cpu_s="n/a"
if [ -n "$cpu_usec0" ] && [ -n "$cpu_usec1" ]; then
    cpu_s=$(awk -v d=$((cpu_usec1 - cpu_usec0)) 'BEGIN{printf "%.2f", d/1e6}')
fi
mhz_mean=0
[ "$mhz_n" -gt 0 ] && mhz_mean=$((mhz_sum / mhz_n))
echo "guard_run: exit=$rc cap=${MAX_MIB}MiB peak=$((peak/1048576))MiB" \
     "wall_s=${wall} cpu_s=${cpu_s} mhz=${mhz_min}/${mhz_mean}/${mhz_max}(min/mean/max)" \
     "load=${load0}→${load1} memavail=${avail0}→${avail1}MiB" \
     "unit=${unit:-n/a}" >&2
exit "$rc"

#!/usr/bin/env python3
"""Resource sampler for a Raspberry Pi 5 -- run as root for the length of a campaign; one JSON line per tick.
usage: resmon.py OUT.jsonl [HZ]      stop with SIGTERM.
Per tick: t (epoch), cpu (the aggregate /proc/stat jiffies), net ({iface: [rx_bytes, rx_pkts, tx_bytes, tx_pkts]}),
units ({p2p unit: cgroup cpu usage_usec}), rss ({unit: VmRSS kB of its main process}), temp_mC, freq_khz, mem_avail_kB, throttled,
pmic ({rail: [amps, volts]}) -> total rail power is sum(V*I) over rails that have both."""
import glob, json, os, re, signal, subprocess, sys, time
OUT = sys.argv[1]; HZ = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0
stop = False
signal.signal(signal.SIGTERM, lambda *a: globals().__setitem__("stop", True))
signal.signal(signal.SIGINT, lambda *a: globals().__setitem__("stop", True))
UNITS = sorted(os.path.basename(p)[:-8] for p in glob.glob("/etc/systemd/system/p2p-*.service"))
def mainpid(u):
    try:
        return int(subprocess.run(["systemctl", "show", "-p", "MainPID", "--value", u], capture_output=True, text=True).stdout.strip() or 0)
    except Exception:
        return 0
PIDS = {u: mainpid(u) for u in UNITS}
def rd(p):
    try:
        with open(p) as f: return f.read()
    except OSError:
        return ""
rail = re.compile(r"\s*(\w+)_([AV]) (?:current|volt)\(\d+\)=([0-9.]+)[AV]")
def pmic():
    try:
        out = subprocess.run(["vcgencmd", "pmic_read_adc"], capture_output=True, text=True, timeout=2).stdout
    except Exception:
        return {}
    r = {}
    for m in rail.finditer(out):
        r.setdefault(m.group(1), [None, None])[0 if m.group(2) == "A" else 1] = float(m.group(3))
    return {k: v for k, v in r.items() if v[0] is not None and v[1] is not None}
with open(OUT, "w") as fo:
    fo.write(json.dumps({"meta": {"units": UNITS, "pids": PIDS, "hz": HZ, "clk_tck": os.sysconf("SC_CLK_TCK"), "host": os.uname().nodename,
                                  "t0": time.time()}}) + "\n")
    period = 1.0 / HZ; nxt = time.time()
    while not stop:
        t = time.time()
        cpu = [int(x) for x in rd("/proc/stat").split("\n", 1)[0].split()[1:9]]
        net = {}
        for l in rd("/proc/net/dev").splitlines()[2:]:
            n, _, rest = l.partition(":"); f = rest.split()
            if len(f) >= 10: net[n.strip()] = [int(f[0]), int(f[1]), int(f[8]), int(f[9])]
        units, rss = {}, {}
        for u in UNITS:
            m = re.search(r"usage_usec (\d+)", rd(f"/sys/fs/cgroup/system.slice/{u}.service/cpu.stat"))
            if m: units[u] = int(m.group(1))
            if PIDS.get(u):
                m = re.search(r"VmRSS:\s+(\d+)", rd(f"/proc/{PIDS[u]}/status"))
                if m: rss[u] = int(m.group(1))
        m = re.search(r"MemAvailable:\s+(\d+)", rd("/proc/meminfo"))
        row = {"t": t, "cpu": cpu, "net": net, "units": units, "rss": rss, "temp_mC": int(rd("/sys/class/thermal/thermal_zone0/temp") or 0),
               "freq_khz": int(rd("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq") or 0), "mem_avail_kB": int(m.group(1)) if m else None,
               "pmic": pmic(), "t_end": time.time()}
        fo.write(json.dumps(row, separators=(",", ":")) + "\n")
        nxt += period
        d = nxt - time.time()
        if d > 0: time.sleep(d)
        else: nxt = time.time()

#!/usr/bin/env python3
"""matrix_run.py + resource accounting: per run the epoch start/end and the sender process tree's rusage (wait4 includes the QUIC helper /
DTLS worker children): cpu_user_s, cpu_sys_s, maxrss_kb, ctx switches, page faults.
usage: matrix_run2.py OUT.jsonl RECEIVER REPS SIZES(comma bytes) TECH [TECH...]    (env MX_PREFIX, CHUNK_PACE_S as before)"""
import hashlib, json, os, subprocess, sys, time
out, recv, reps, sizes = sys.argv[1], sys.argv[2], int(sys.argv[3]), [int(x) for x in sys.argv[4].split(",")]
techs = sys.argv[5:]
files = {}
for n in sizes:
    p = f"/tmp/mx-{n}.bin"
    if not os.path.exists(p):
        open(p, "wb").write(os.urandom(n))
    files[n] = (p, hashlib.sha256(open(p, "rb").read()).hexdigest())
with open(out, "a") as fo:
    for tech in techs:
        for n in sizes:
            p, sha = files[n]
            for i in range(reps + 1):
                dest = f"{os.environ.get('MX_PREFIX', 'mx')}-{tech}-{n}-{i}.bin"
                t_wall = time.time(); t0 = time.monotonic()
                of, ef = open("/tmp/mx2.out", "w+"), open("/tmp/mx2.err", "w+")
                proc = subprocess.Popen(["python3", "/opt/p2p/sender-role/cli.py", "deliver", recv, p, dest, "--tech", tech, "--timeout", "120"],
                                        stdout=of, stderr=ef, text=True, cwd="/opt/p2p/sender-role")
                _, wstatus, ru = os.wait4(proc.pid, 0)          # rusage of the CLI AND everything it started and waited for
                proc.returncode = os.waitstatus_to_exitcode(wstatus)
                wall = (time.monotonic() - t0) * 1000; t_end = time.time()
                of.seek(0); ef.seek(0); stdout, stderr = of.read(), ef.read(); of.close(); ef.close()
                try:
                    j = json.loads(stdout)
                except Exception:
                    j = {"ok": False, "unparsed_stdout": stdout[-400:]}
                row = {"tech": tech, "size": n, "rep": i, "warmup": i == 0, "rc": proc.returncode, "wall_ms": round(wall, 1),
                       "t_start": t_wall, "t_end": t_end, "sha_expected": sha, "sha_match": j.get("sha256") == sha,
                       "stderr_tail": stderr[-300:],
                       "rusage": {"cpu_user_s": round(ru.ru_utime, 4), "cpu_sys_s": round(ru.ru_stime, 4), "maxrss_kb": ru.ru_maxrss,
                                  "nvcsw": ru.ru_nvcsw, "nivcsw": ru.ru_nivcsw, "minflt": ru.ru_minflt, "majflt": ru.ru_majflt},
                       "result": j}
                fo.write(json.dumps(row) + "\n"); fo.flush()
                t = (j.get("timing") or {})
                print(f"{tech:22s} {n:7d} #{i} rc={proc.returncode} ok={j.get('ok')} sha={row['sha_match']} total={t.get('total_ms')} wall={wall:.0f}", flush=True)

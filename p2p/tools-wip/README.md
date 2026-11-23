# tools-wip -- UNTESTED drafts for per-transfer RESOURCE metrics (not part of any verified result)
* `resmon.py`   Pi-5 sampler (20 Hz): /proc/stat CPU, /proc/net/dev per interface (wg0 + underlay), cgroup cpu usage of each p2p-* unit, VmRSS of their main pids,
                temperature, cpu freq, `vcgencmd pmic_read_adc` rail currents/voltages (power = sum V*I; one call costs ~23 ms). One JSON line per tick.
* `matrix_run2.py`  matrix_run.py + `t_start`/`t_end` epoch per run and the sender process tree's rusage via `os.wait4` (cpu user/sys, maxrss, ctx switches).
Idea: start `resmon.py` on both Pis, run `matrix_run2.py` on the sender, align the samples to each run's [t_start, t_end] (clock offset per Pi from `ssh date`),
subtract an idle baseline. Never run end to end -- finish, test and validate before quoting any number from it.

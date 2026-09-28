# Tasks

## Open

- [ ] Resolve the iQOO 15 kernel identity. `f4e7c88f` registers
      `6.12.23-android16-5-ge4db19ad2c57-abogki451864203-4k` (from
      `D:\R2-Vivo-iQOO-15-PD2505.zip`). The `D:\iqoo15s` image is a different
      build, `6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k`, which the
      extractor rejects as infeasible (exit 3, pselect shift 14 qwords, no mcast
      stamp). If the phone runs 6.12.58, the registered entry supports a kernel
      nothing runs and should be removed. Confirm with `adb shell uname -r`.

- [ ] tcp route on 6.6 / 6.12. Not started, and not a port.
      The route in `src/core/fops.c` (`do_tcp_fake_lock_route`) is a copy of
      Root-My-Pixel-Payloads `src/61/fops.c`, and RMGP's tcp targets are all
      5.15/6.1. No 6.6 or 6.12 tcp route exists in either codebase.
      What is missing: where the stale waiter's `task` (0x50) and `lock` (0x58)
      sit relative to the `getsockopt(TCP_ZEROCOPY_RECEIVE)` plant. Four
      disassembly attempts disagreed; source reading shows the plant is the
      `copy_from_sockptr(&zc, optval, len)` in `do_tcp_getsockopt` and the waiter
      lives in that function's zeroed stack buffer, and the link between the two
      is not visible in either. Forcing it with `GHOSTLOCK_TCP_ROUTE=1` panics
      dada 6.6.77.
      To do it properly: one kernel at a time, establish the overlap from a
      device signal (the route prints the page address if it lands), not from
      frame arithmetic. See `tcp-route-local-offset-model` in memory.

- [ ] pselect attempt count sweep. `GHOSTLOCK_PSELECT_ATTEMPTS` (default 4) and
      `GHOSTLOCK_TCP_ATTEMPTS` (default 2000) are tunable but unmeasured.
      Duchamp 6.1 wins tcp at `seq=16`, so the attempts cap was not exercised.

## Done this session

- [x] tcp attempts 128 -> 2000 (`54ddd6ea`), matching upstream's config.
- [x] Reverted the hold unit and nice-rotation edits back to upstream's
      constants (`0eed59e8`).
- [x] 5.15 refuses incomplete mcast geometry instead of falling to pselect
      (`dd856bbf`), with a host test (`8ae87a34`).
- [x] Compact pselect attempts made env-tunable (`8d342942`).
- [x] iQOO 15 6.12.23 offsets registered (`f4e7c88f`) - see open item above.
- [x] Recorded why the tcp gate needs the compact waiter (`4558f5ad`).
- [x] Duchamp 6.1 tcp route device-verified: `tcp route won seq=16`,
      child uid=0, KernelSU ready.

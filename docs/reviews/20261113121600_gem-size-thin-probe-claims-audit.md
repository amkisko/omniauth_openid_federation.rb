# Gem size and thin-probe claims audit

## Participants

Andrei Makarov (@amkisko)

## Decisions

- Treat the pasted thin-probe / gem-size note as a claims ledger, not as an accepted measurement freeze.
- Remeasure with primary artifacts: gem build, `du -sk` on extracted payload, cold `require` via `/usr/bin/time -l`, and `benchmarks/cooker.rb` calibrate / measure / gate / prove at L1.
- Distinguish macOS `du` block accounting from sum-of-file-bytes (apparent size). They are not interchangeable.

## Effects

### Contrary pass (before constructive ledger)

- Installed gem near 900 KiB can be block-rounded `du`, while apparent payload is near 674 KiB; calling both "size" without naming the meter mixes quantities.
- `lib ~612 KiB` matches `du -sk lib` on the extracted gem, not the sum of file bytes (~454 KiB).
- Disk growth +36 KiB matches installed-gem `du` from 2.1.0 (864K) to 2.2.1 (900K). Named split lib +28 / examples +4 sums to +32; the remaining +4K is other packaged paths (docs and related), not only those two.
- Wall/cpu/RSS +5-8 percent for thin-probe is not reproducible on an isolated gem `require` of tag `2.1.0` lib versus HEAD (medians moved slightly down or within noise).
- Web-boot RSS +~5 MiB and auth-cluster `du` -52 KiB have no in-repo host probe; unverifiable here.
- "No security problem" for package-size growth is not a security audit of federation auth paths.
- Eager-loading tasks cuts disk and feature count; cold-boot wall/cpu/RSS delta for skipping `tasks_helper` stayed inside sample noise (wall median unchanged; cpu about +0.01 s; RSS about +0.6 MiB with wide sample spread).
- Cooker `rss_delta_bytes` reported 0 on this host; do not treat that series as a memory gate without a working RSS meter.

### Claim ledger

1. Location: lead verdict. Claim: no regression and no security issue; growth expected and small. Outcome: partially supported. Gate/smoke ceilings pass for this tree; size growth is small. Security claim is out of scope for size metrics alone.
2. Location: thin-probe disk +36 KiB; lib +28; examples +4. Outcome: supported for total installed-gem `du` 864K to 900K and for lib/examples `du` deltas; qualify remainder +4K.
3. Location: wall/cpu/RSS about +5-8 percent; head cold outlier 410 ms; medians in noise. Outcome: unverifiable for the unnamed host thin-probe; unsupported for isolated gem require 2.1.0 versus HEAD in this session (wall median 0.42 s to 0.39 s; cpu 0.29 s to 0.28 s; RSS +0.57 percent).
4. Location: web-boot RSS +~5 MiB while auth-cluster du even -52 KiB; disk != resident; not a delivery blocker. Outcome: unverifiable here (no host web-boot probe). Disk != resident is supported as a general measurement rule.
5. Location: installed gem already ~900 KiB (~1 MiB). Outcome: supported as `du -sk` of extracted 2.2.1 payload (900K). Apparent file sum is 690558 bytes (~674 KiB). Compressed `.gem` is 150016 bytes.
6. Location: lib ~612 KiB real federation code. Outcome: supported as `du -sk` (612K). Apparent ~454 KiB. Content claim (trust chain, JWKS, strategy) supported by tree layout.
7. Location: examples ~196 KiB; packaged; not runtime. Outcome: supported (`du` 196K; in gemspec `examples/**/*`; not required by main entry).
8. Location: sig ~28 KiB RBS. Outcome: supported (`du` 28K; apparent ~21 KiB).
9. Location: require loads 65 federation files including tasks_helper + 5 task classes. Outcome: supported (remeasured 65 features; tasks_helper plus five under `tasks/`).
10. Location: `.gem` ~150 KiB packed; ~900 KiB unpacked. Outcome: supported with meter named (compressed file vs `du` install tree).
11. Location: suggestion remove examples from gemspec for ~200 KiB win. Outcome: partially supported. Uncompressed examples ~160 KiB apparent / 196K `du`; approximate data.tar.gz contribution ~36 KiB. "About 200 KiB" fits `du` language, not compressed ship size.
12. Location: do not eager-require tasks; loads only from rake / tasks entry. Outcome: supported that main entry requires tasks_helper today; boot savings claim only weakly supported (noise).
13. Location: consider lazy/autoload for unused federation/strategy modules. Outcome: testimony / design suggestion; not measured this episode.
14. Location: sig may stay or move to -types. Outcome: testimony.
15. Location: do not add rfcs/ to the gem; keep current exclusion. Outcome: supported (gemspec and extracted payload have zero `rfcs/` paths).
16. Location: optional future rails gem split. Outcome: testimony.

### Benchmark freeze (this session)

Commands and observed results:

- `gem build omniauth_openid_federation.gemspec` -> `omniauth_openid_federation-2.2.1.gem` 150016 bytes; data payload 103 files, 690558 bytes.
- `du -sk` extracted 2.2.1 payload -> 900; parts lib 612, examples 196, sig 28.
- `du -sk` extracted 2.1.0 payload -> 864; lib 584, examples 192, sig 28. Delta total +36.
- Cold require HEAD (`/usr/bin/time -l bundle exec ruby -Ilib -e 'require "omniauth_openid_federation"'`, n=5): wall median 0.37 s, cpu median 0.27 s, RSS median 52641792.
- Empty ruby process n=5: wall 0.20 s, cpu 0.13 s, RSS 26689536.
- Tag compare require (2.1.0 lib tree vs HEAD lib, n=5 each): wall 0.42 -> 0.39; cpu 0.29 -> 0.28; RSS 51806208 -> 52101120.
- Skip tasks_helper require (patched entry, n=5): wall median unchanged 0.37; cpu 0.26 vs 0.27; RSS 50872320 vs 51478528.
- `SCENARIO=calibrate bundle exec ruby benchmarks/cooker.rb` -> PASS.
- `SCENARIO=measure LOAD=L1 SAMPLES=3` -> wall_s median about 0.403 s; allocated_objects median 12233; rss_delta_bytes 0.
- `SCENARIO=gate LOAD=L1 SAMPLES=3` -> pass true, failures [].
- `SCENARIO=prove LOAD=L1 SAMPLES=3` -> wall_s about 0.422 s; under ceilings in `benchmarks/ceilings.json`.
- Local smoke ceilings from release reviews still fit: compressed gem under 1 MiB; cold RSS under 128 MiB; cpu under 2 s.

### Maintainer priority check

1. Drop `examples/**/*` from gemspec: still the clearest packaged-byte win; cite `du` or apparent bytes explicitly.
2. Stop eager-requiring tasks: correct dependency hygiene; do not promise large boot RSS/CPU wins without a tighter probe.
3. Lazy/autoload: optional; prove with a named series first.
4. Keep `sig/` and keep `rfcs/` out: agree.

## Next

- If a host thin-probe claimed +5-8 percent wall/cpu/RSS, re-run that exact probe with frozen base/head and n>=3; do not reuse this gem-only require delta as confirmation.
- Fix or replace cooker RSS capture before writing memory ceilings from `rss_delta_bytes` on this host.
- Optional follow-up: lazy/autoload unused federation modules after a named series prove.

### Later pass (2026-11-13): examples exclusion and deferred tasks require

- Implemented: gemspec drops `examples/**/*`; main entry omits `tasks_helper`; new `omniauth_openid_federation/tasks` entry; rake and integration example updated; packaging and tasks-entrypoint specs green (34 focused examples, 0 failures with related rake/resolve specs).
- Packaging freeze before -> after: gem bytes 150016 -> 114688; apparent payload 690558 -> 526663; `du -sk` 900 -> 708; examples removed from package.
- Cold-require freeze after: main 59 federation features, TasksHelper no; tasks entry 66 features, TasksHelper yes (n=5).
- Engineering note: `docs/changelogs/20261113123000_exclude-examples-defer-tasks-require.md`.

## Source

- Pasted maintainer note under review (chat)
- `omniauth_openid_federation.gemspec`
- `lib/omniauth_openid_federation.rb`
- `lib/omniauth_openid_federation/tasks_helper.rb`
- `benchmarks/cooker.rb`
- `benchmarks/ceilings.json`
- `docs/reviews/20261111205000_engineering-audit-release-preparation.md`
- `docs/reviews/20261111160744_engineering-audit-release-preparation.md`
- Tags `2.1.0`, `2.2.0`, `2.2.1`

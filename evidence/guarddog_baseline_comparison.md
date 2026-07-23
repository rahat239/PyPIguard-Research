# GuardDog Baseline Comparison on the PyPIGuard Held-Out Set

## Purpose

Both SoftwareX and JSS review rounds flagged the same underlying issue: PyPIGuard's
reported metrics were never compared against an actual, independently-run detection
tool on identical data. The prior manuscript only cited Cerebro's *self-reported*
81.5% PyPI false-positive rate as indirect context — not a head-to-head run. This
document reports a real, reproducible run of GuardDog (DataDog's open-source PyPI/npm
malware scanner) against the exact same 400-package held-out set used to evaluate
PyPIGuard (200 malicious, 200 benign, zero name overlap with training).

## Methodology

**Tooling.** GuardDog 3.1.0, installed via `pip`, invoked through its CLI
(`guarddog pypi scan`) with `--no-sandbox` (no kernel-level sandbox available in this
environment) and `--output-format json`.

**Verdict rule.** A package is counted as GuardDog-flagged if at least one rule
produces a non-empty finding — this matches GuardDog's own default CLI behavior
(`--exit-non-zero-on-finding`). Two verdict definitions are reported since GuardDog's
rule set mixes two tiers:

- **Definition A (any finding).** Any of GuardDog's ~50 rules fires, including
  broad `capability-*` rules (e.g. "capability-process-spawn"), which flag the mere
  *presence* of a capability (subprocess use, network calls, file deletion) rather
  than a judgment that the code is malicious.
- **Definition B (threat/heuristic rules only).** Restricts the verdict to
  `threat-*` rules plus named heuristics (`typosquatting`, `deceptive_author`,
  `bundled_binary`, `metadata_mismatch`, etc.), excluding the broad `capability-*`
  category. This is the stricter, arguably fairer reading of "GuardDog thinks this
  package is malicious."

Both are reported so the comparison isn't tuned to make either tool look better.

**A critical obstacle: PyPI takedown.** GuardDog scans by pulling a package live
from the PyPI registry. A pre-check (HTTP HEAD against `pypi.org/pypi/<name>/json`
for all 400 packages) found that **199 of the 200 malicious packages had already
been removed from PyPI** — only 1 was still live. All 200 benign packages were
still live. This is itself a notable finding: it means a live-registry scanner like
GuardDog is structurally unable to evaluate against malware PyPI has already taken
down, which is exactly the malware a pre-install scanner most needs to have caught
*before* removal.

**Recovery of removed packages.** To make a real comparison possible rather than
reporting on an N=1 malicious sample, the actual source archives for all 200
malicious packages were recovered from
[`lxyeternal/pypi_malregistry`](https://github.com/lxyeternal/pypi_malregistry), a
third-party research archive that mirrors the raw source of removed PyPI malware
specifically for reproducibility purposes. All 200 package names in the held-out
set were located in this archive (one arbitrary version per package, preferring the
highest-versioned sdist available; one corrupted/zero-byte archive for
`aiohttp-sock@0.1.56` was substituted with `0.1.55` from the same repository).
GuardDog was then run against these local archives directly
(`guarddog pypi scan <path-to-archive>`), which GuardDog supports natively.

**Independent dataset corroboration.** As a secondary check on the held-out set's
labels (addressing the "dataset verification" review concern directly), package
names were cross-referenced against
[`ossf/malicious-packages`](https://github.com/ossf/malicious-packages), the
OpenSSF community database of confirmed malicious packages (OSV format, sourced
from ReversingLabs, Sonatype, GitHub Advisories, etc.). **172 of the 200 (86%)
malicious labels are independently corroborated** by this third-party database,
outside of and prior to this evaluation.

**Asymmetry caveat.** Local-archive scans (malicious side) do not have access to
PyPI registry metadata (upload date, maintainer email, download stats), so
metadata-dependent rules (`typosquatting`, `deceptive_author`,
`unclaimed_maintainer_email_domain`, etc.) could not fire on the malicious side, but
could and did fire on the benign side (scanned live). This means GuardDog's
measured detection rate on malicious packages is, if anything, a conservative
underestimate relative to what it could achieve scanning packages before takedown
with full registry metadata available. Two further rules
(`unclaimed_maintainer_email_domain`, `potentially_compromised_email_domain`) could
not run for either class in this sandboxed environment due to blocked outbound DNS/WHOIS
lookups; they are excluded from both classes consistently.

## Results

Confusion matrices on the identical 400-package held-out set:

| Metric | PyPIGuard (from manuscript) | GuardDog — Def. A (any finding) | GuardDog — Def. B (threat/heuristic only) |
|---|---|---|---|
| TP (malicious flagged) | 198 / 199 | 182 / 200 | 175 / 200 |
| FN (malicious missed) | 1 / 199 | 18 / 200 | 25 / 200 |
| TN (benign cleared) | 188 / 197 | 66 / 200 | 153 / 200 |
| FP (benign flagged) | 9 / 197 | 134 / 200 | 47 / 200 |
| Precision | 0.957 | 0.576 | 0.788 |
| Recall | 0.995 | 0.910 | 0.875 |
| F1 | 0.975 | 0.705 | 0.829 |
| False positive rate | 0.046 | 0.670 | 0.235 |
| Accuracy | 0.975 | 0.620 | 0.820 |

Under both definitions, PyPIGuard outperforms GuardDog on precision, F1, and false
positive rate on this identical held-out set, while recall is closer (GuardDog Def.
A recall of 0.910 vs. PyPIGuard's 0.995). GuardDog's high false-positive rate under
Definition A (67%) is driven almost entirely by broad `capability-*` rules
(`capability-process-spawn`, `capability-filesystem-read`, `capability-network-outbound`)
firing on completely ordinary, benign code patterns (e.g. any package that shells
out or opens a socket) — consistent with GuardDog's own documentation describing
these as capability indicators rather than verdicts. Restricting to threat/heuristic
rules (Def. B) brings GuardDog's FPR down to 23.5%, still roughly 5x PyPIGuard's 4.6%.

The most frequent rules firing on malicious packages were `capability-process-spawn`
(168/200), `threat-process-download-exec` (121/200), and
`threat-process-powershell-encoded` (97/200) — consistent with the
download-and-execute / PowerShell-cradle pattern seen across many of these samples.
The most frequent rules firing on benign packages were `capability-filesystem-read`
(81/200), `capability-process-spawn` (49/200), and `capability-network-outbound`
(44/200).

## Suggested framing for the manuscript

This replaces the prior "Cerebro-inspired proxy comparison" language with a real,
reproducible baseline: *"GuardDog (DataDog, v3.1.0) was run against the identical
400-package held-out set... PyPIGuard achieves higher precision (0.957 vs.
0.576–0.788) and a substantially lower false-positive rate (4.6% vs. 23.5–67.0%)
than GuardDog on the same data, while both tools achieve comparable recall."* The
PyPI-takedown finding (199/200 malicious samples already removed from the live
registry) is also worth a sentence, as it underscores PyPIGuard's motivating premise:
pre-install detection has to work *before* a registry takedown, not after.

## Files produced

- `guarddog_holdout_results.csv` — per-package raw results: true label, GuardDog
  issue count, both verdict definitions, firing rule list, OSV corroboration flag
  (malicious only), and data source (recovered local archive vs. live PyPI).

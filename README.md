# PyPIGuard: Detecting Malicious PyPI Packages Using Machine Learning

A lightweight, explainable, LLM-free machine learning system for detecting malicious PyPI
packages using static code, AST-derived, and structural features. Validated through an
extensive battery of experiments including cross-ecosystem generalization, adversarial
evasion robustness, temporal validation, independent secondary-dataset testing, and a
real head-to-head comparison against an existing open-source scanner (GuardDog). Deployed
as a live, public web application and, as of v1.2, as an installable Python library/CLI.

**Live demo:** https://rahat239.github.io/Malware-classifier/

**Current version:** v1.2 (see [Reliability fixes](#reliability-fixes-v11-v12) below for what changed and why)

## Headline Results

**A note on the ROC-AUC/recall figures below, read this first:** the 0.998/0.995
name-disjoint numbers are the standard held-out evaluation, but a direct check found
they are inflated by template-level duplication (see "Known limitation" below). The
0.983/0.940 cluster-disjoint numbers are the more defensible estimate of real-world
generalization. Both are reported for transparency; the cluster-disjoint figure should
be treated as the headline result, not the name-disjoint one.

| Metric | Name-disjoint (inflated) | Cluster-disjoint (defensible) |
|---|---|---|
| ROC-AUC | 0.998 | 0.983 |
| Precision | 0.957 | 0.978 |
| Recall | 0.995 | 0.940 |
| F1 | -- | 0.959 |
| FPR | 4.6% | 3.8% |

| Other metric | Value |
|---|---|
| Temporal validation ROC-AUC (train pre-cutoff, test post-cutoff) | 0.984 |
| Adversarial evasion flip rate (final model) | 2% (down from 9% pre-AST-integration) |
| Cross-ecosystem (npm) ROC-AUC | 0.815-0.818 |
| GuardDog head-to-head FPR (identical held-out set) | PyPIGuard 4.6% vs. GuardDog 67.0%/23.5% |
| Model inference latency (single request, corrected) | 6.8-7.4 ms |
| Training set size | 9,723 samples (7,960 malicious, 1,763 benign) |
| Training time (full retrain) | 2.3 s on a single commodity CPU core |

### Known limitation: name-disjoint splitting does not catch feature-level duplication

Malicious PyPI campaigns routinely copy-paste one payload across many typosquat names.
A direct check on the full training population found 89.8% of the 7,960 malicious
training packages share a near-duplicate feature vector with another package (808
distinct templates total). Checking the 200 held-out malicious packages against a
1,500-package training-adjacent sample: 76 (38.0%) are exact feature-vector duplicates,
186 (93.0%) are near-duplicates. A cluster-disjoint re-evaluation (splitting whole
near-duplicate clusters, never individual packages, between train and test) gives the
0.983/0.940/0.978/0.959/3.8% figures in the table above, and is the number this project
considers the honest estimate of real-world generalization. Full methodology in the
paper and `notebooks/`.

## Repository Structure

```
├── data/               Datasets (training, held-out validation, cross-ecosystem, evasion test pairs)
├── notebooks/          Model development, validation, and all extended experiments
├── src/                Feature extraction modules (AST-based, bytecode-level, behavior-sequence)
├── models/             Trained model artifacts (joblib) -- see pypiguard/data/ for the
│                       version actually shipped in the installable package (v1.2)
├── paper/              Full paper draft (Markdown)
├── pypiguard/          NEW (v1.2): installable library + CLI, factored out of webapp/app.py
│                       so the web app and CLI share one detection core. See below.
├── webapp/             Deployable Flask web application (live scanner + notebook scanner);
│                       now imports from pypiguard/ rather than duplicating logic
├── .github/workflows/  NEW (v1.2): pypiguard-check.yml, a ready-to-use CI/CD dependency-scan
│                       GitHub Action (see Reuse section below)
└── docs/               Additional documentation
```

## Dataset Sources

- **Malicious PyPI samples:** [`lxyeternal/pypi_malregistry`](https://github.com/lxyeternal/pypi_malregistry)
  — official artifact of *"An Empirical Study of Malicious Code In PyPI Ecosystem"* (ASE 2023).
  This repository is large (~700MB); it is not included in this repo. To reproduce feature
  extraction from raw source, clone it separately:
  ```bash
  git clone https://github.com/lxyeternal/pypi_malregistry.git
  ```
- **Benign PyPI samples:** [PyPI's official package index](https://pypi.org/simple/) and
  [JSON API](https://pypi.org), randomly sampled.
- **Cross-ecosystem (npm) malicious samples:** [`DataDog/malicious-software-packages-dataset`](https://github.com/DataDog/malicious-software-packages-dataset).
- **Cross-ecosystem (npm) benign samples:** the official [npm registry](https://registry.npmjs.org).
- **Independent label corroboration:** [`ossf/malicious-packages`](https://github.com/ossf/malicious-packages)
  (OpenSSF's community-maintained OSV-format malicious-package database, sourced from
  ReversingLabs, Sonatype, and GitHub Advisories). 172/200 of our held-out malicious labels
  are independently corroborated here.

The processed feature datasets in `data/` are the actual data used for all reported results;
the raw source archives above are only needed to re-run feature extraction from scratch.

## Independent Verification & Baseline Comparison

These address the concern that this project's dataset comes from a single source and that
the state-of-the-art comparison was previously weak.

- **Label corroboration:** 172/200 (86%) of held-out malicious labels independently
  confirmed against OpenSSF's `malicious-packages` database, established outside of and
  prior to this evaluation.
- **Secondary generalization set:** a second, fully disjoint 400-package evaluation set
  (200 malicious + 200 benign, zero name overlap with training or the primary held-out set)
  gives a genuine out-of-sample result: 0.959 precision, 0.930 recall, 0.944 F1, 4.0% FPR
  under the unmodified v1.0 model.
- **GuardDog head-to-head:** [GuardDog](https://github.com/DataDog/guarddog) (DataDog's
  open-source PyPI/npm scanner, v3.1.0) was run against the *identical* 400-package held-out
  set. 199/200 malicious packages had already been removed from the live PyPI registry by
  evaluation time, so original source archives were recovered from `pypi_malregistry` and
  scanned locally; benign packages were scanned live. Two rule-inclusion readings are
  reported (any rule fires vs. threat/heuristic rules only):

  | Metric | PyPIGuard | GuardDog (any rule) | GuardDog (threat rules only) |
  |---|---|---|---|
  | Precision | 0.957 | 0.576 | 0.788 |
  | Recall | 0.995 | 0.910 | 0.875 |
  | F1 | 0.975 | 0.705 | 0.829 |
  | False positive rate | 0.046 | 0.670 | 0.235 |

- **Resource/training-cost comparison against Cerebro and MalGuard:** since neither has
  released code, this compares our measured figures against each baseline's own published
  numbers (not head-to-head, stated as such). PyPIGuard trains the full 9,723-sample model
  in 2.3s on a single CPU core, vs. Cerebro's self-reported 14-25 hours and vs. 2,439s
  (Cerebro) / 30,741.67s (EA4MP) as independently re-run by the MalGuard authors. Per-package
  feature extraction: 0.9ms (median) for PyPIGuard vs. 12.489s (Cerebro) / 6.28s (EA4MP) per
  MalGuard's measurements -- a three-to-four order-of-magnitude gap. As a cross-check,
  MalGuard's own GuardDog evaluation (95.6% precision, 82.6% recall on different data) is
  broadly consistent with our measured GuardDog range above.

## Reliability Fixes (v1.1, v1.2)

Both fixes below were found through deployment/reuse testing, root-caused, fixed via
targeted hard-negative retraining (never a heuristic filter), and shipped only after their
full trade-off was measured and found acceptable -- both directions of each change are
reported here, not just the improvement.

### v1.1: the `requests` misclassification

`requests`, this project's own illustrative example, was misclassified as malicious in 3 of
5 tested historical versions (v0.2.0, v0.9.2, v2.2.0, v2.17.0, v2.34.2 tested; v2.2.0,
v2.17.0, v0.2.0 misclassified). A prior draft attributed this uniformly to vendored
third-party dependencies (e.g. bundled urllib3/chardet). Re-investigating with a per-file
breakdown of which code contributed which flagged pattern:
- v2.2.0: genuinely due to vendored urllib3/chardet, including a real `getattr`-obfuscation
  match inside vendored `six.py`.
- v2.17.0: vendors nothing. False flags (`os.system`, `exec`, `cmdclass`, raw sockets) come
  entirely from `setup.py` packaging boilerplate (a `publish` shortcut invoking
  `twine upload`, and the `exec(f.read(), about)` idiom for loading version metadata) and
  the `tests/` directory (a local test HTTP server, a serialization test).
- v0.2.0: packaging boilerplate in `setup.py`, compounded by very small package size.

**Root cause:** non-runtime code (build scripts, test suites) is treated identically to
shipped runtime code by the feature extractor, AND `requests` and its common dependencies
were entirely absent from the 9,723-sample training set.

**Rejected fix:** a feature-extraction-level filter excluding `tests/` content and two
benign `setup.py` idioms. Evaluated across the full 400-package held-out set, this produced
no net false-positive reduction and introduced new false negatives on real malicious
packages that clone `requests`' test suite to camouflage themselves. Not adopted.

**Shipped fix:** added 7 hard-negative training examples (3 historical `requests` releases,
4 `chardet`/`six` releases) as new benign samples; retrained the identical Random Forest
architecture (300 estimators, unchanged hyperparameters, 2.3s). Result: all 5 `requests`
versions now classify correctly; primary held-out set improves (F1 0.978→0.983, FPR
4.04%→3.03%).

**Measured cost:** on the independent secondary set, recall drops 93.0%→91.0% (F1
0.944→0.936): 5 malicious packages previously caught are now missed. All 5 were already
near-decision-boundary (51-62% confidence) in v1.0, not confident detections lost. One,
`requests-testik11`, is a byte-for-byte clone of a real `requests` release with zero
injected code -- a limitation inherent to static analysis generally (no code-content
classifier can distinguish a perfect clone from the original), not specific to this fix.
Sample-weight sweeping (0.1x-5x) confirmed this trade-off is intrinsic to correcting the
training-data gap, not a tunable side effect (one lighter-weight configuration performed
*worse*).

A path-traversal ("zip-slip") vulnerability, found and patched via a crafted adversarial
test archive prior to deployment, is noted here for the same transparency reason.

### v1.2: the `typing-extensions` misclassification (found via reuse testing)

Found while dogfooding the new CLI (see [Reuse](#reuse-library-cli-and-cicd-integration)
below) against `black`'s actual PyPI-declared core dependencies -- a genuine, non-curated
case study, not a synthetic demo. 7/8 dependencies cleared correctly; `typing-extensions`
(a foundational, extremely widely-used Python typing-compatibility package maintained
alongside CPython itself) was flagged malicious at 68.0% confidence.

**Root cause:** identical pattern to `requests`. The sdist bundles CPython's own
`typing_extensions` test suite (9,768 lines) alongside the 4,422-line runtime module; the
test file alone accounts for the eval/exec/subprocess/pickle indicators that drove the
flag, while the runtime module's legitimate, version-compatibility-driven heavy use of
`getattr()` (20 call sites) contributed further. This confirms the root cause generalizes
beyond one package family, not a `requests`-specific fluke.

**Shipped fix:** 8 historical `typing-extensions` releases added as hard-negative training
examples; retrained (v1.2, still 2.3s); full regression check re-run across both held-out
sets (796 evaluable cases total).

**Result:** `typing-extensions` now classifies correctly (80.7% confidence, benign); all 5
`requests` versions remain correctly classified. Combined across both held-out sets:
precision 0.967→0.955, F1 0.960→0.954 (9 new misclassifications, 4 corrected, net -5). Every
one of the 13 affected cases sits at 50-60% confidence in *both* model versions -- i.e.
cases the model was already nearly undecided on, not confident detections gained or lost.

## Reuse: Library, CLI, and CI/CD Integration

As of v1.2, the detection core (feature extraction + model inference) is factored out of
`webapp/app.py` into a standalone `pypiguard/` package, so the web app and the new CLI are
two consumers of one detection core rather than the web UI being the only way to invoke it.

**Install:**
```bash
pip install .
```

**CLI usage:**
```bash
# Scan a live PyPI package by name
pypiguard scan requests

# Scan a local archive
pypiguard scan-file /path/to/package.tar.gz

# Scan every dependency in a requirements.txt -- exits 1 if any is flagged (for CI)
pypiguard scan-requirements requirements.txt --fail-on-malicious
```

**CI/CD integration:** `.github/workflows/pypiguard-check.yml` is a ready-to-use GitHub
Actions workflow that installs `pypiguard` and runs `scan-requirements --fail-on-malicious`
against a project's `requirements.txt` on every pull request touching dependency files,
failing the build if a flagged package is present. Drop it into any Python project's
`.github/workflows/` directory (adjust the requirements-file path as needed).

This tooling is not just a packaging exercise: running it against `black`'s real
dependencies is precisely what surfaced the v1.2 `typing-extensions` finding above, so it
functioned as an independent reliability check as well as a reuse-oriented deliverable.

## Reproducing the Results

1. Install dependencies:
   ```bash
   pip install -r webapp/requirements.txt
   pip install jupyter nbformat scikit-learn pandas matplotlib seaborn shap scipy
   ```
2. Open `notebooks/Phase4_extended.ipynb` in Jupyter or upload to Google Colab.
3. Run all cells. When prompted (if running in Colab), upload the corresponding CSV files
   from `data/`.

## Running the Web Application Locally

```bash
cd webapp
pip install -r requirements.txt
python app.py
```
Then open http://localhost:5000.

## Citation

If you use this work, please cite:

```bibtex
@misc{pypiguard2026,
  title={PyPIGuard: A Lightweight, Explainable Machine Learning Tool for Pre-Install Detection of Malicious PyPI Packages},
  author={Rahat Ahmed},
  year={2026},
  howpublished={\url{https://github.com/rahat239/PyPIguard-Research}}
}
```

## Key Findings

- A comprehensive static feature set (regex + AST + engineered, 35 features total) achieves
  0.998 ROC-AUC on a name-disjoint held-out set, and 0.983 ROC-AUC on a genuinely
  cluster-disjoint held-out set once feature-level near-duplicate leakage (see "Known
  limitation" above) is accounted for -- the latter is the honest generalization estimate.
- AST-level and bytecode-level analysis substantially improve adversarial evasion robustness
  (flip rate reduced from 9% to 2%) without requiring dynamic/behavioral execution.
- Cross-ecosystem transfer (PyPI-trained model evaluated on real npm packages) is real but
  partial (0.818 ROC-AUC vs. 0.999 in-ecosystem), confirmed stable across two dataset scales.
- Temporal validation confirms generalization to packages discovered after the training
  cutoff (0.984 ROC-AUC), a standard rigor check for malware detection specifically.
- Two deployment/reuse-testing findings (`requests`, `typing-extensions`) were traced
  to the same training-data gap and fixed (v1.1, v1.2), with their reliability
  trade-offs measured and disclosed rather than hidden. A direct generalization test on
  a third, previously-unused package (Django 6.0.7) found the underlying pattern is
  **not resolved in general** -- v1.1/v1.2 fixed the two specific instances discovered,
  not the broader failure mode. Disclosed plainly rather than left untested.
- A labeled, honestly-bounded comparison against a Cerebro-inspired sequence-based baseline
  found the proxy modestly outperforming our tabular approach on matched data (0.983 vs.
  0.967 ROC-AUC), reported transparently rather than selectively.

## Known Limitations

See `paper/pypiguard_softwarex.tex` (the current SoftwareX submission) for the full
discussion; `paper/Phase5_Paper_Draft.md` is an earlier, superseded IEEE-conference-style
draft kept for historical reference and should not be treated as authoritative. In brief:
this is static analysis only (no dynamic/sandboxed execution, a deliberate scope decision
given the safety risk of executing real malware without dedicated isolation infrastructure);
name-disjoint train/test splitting does not catch feature-level near-duplicate leakage (see
"Known limitation" above -- this is the single most consequential finding in this project);
no static-content classifier can distinguish a byte-for-byte clone of a legitimate package
from the original; the Cerebro/MalGuard comparisons are either a labeled sequence-proxy or a
resource-figure comparison, not a reproduction of the original systems (neither has released
public code); model inference latency is 6.8-7.4ms per request (corrected from an earlier,
incorrectly-benchmarked 0.18ms figure); the training dataset remains class-imbalanced
(82%/18%, mitigated with `class_weight="balanced"`); and the v1.1/v1.2 fixes are validated
generalization patches, not a proven-general fix (see Django finding above).

## License

MIT License (see `LICENSE`).

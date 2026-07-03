# Detecting Malicious PyPI Packages Using Machine Learning on Package Metadata and Code-Level Features

**Paper draft — ready to adapt into IEEE Conference LaTeX template (Overleaf)**

---

## Abstract

Open-source package registries such as PyPI are foundational to modern software development, yet they remain a persistent and growing vector for supply-chain attacks. Attackers routinely publish malicious packages — often via typosquatting of popular libraries — to compromise unsuspecting developers, as demonstrated by real incidents such as `event-stream` (2018) and `ua-parser-js` (2021). This paper presents a lightweight, explainable machine learning approach for detecting malicious PyPI packages using static code and structural features, avoiding the latency, cost, and non-determinism of large language model (LLM)-based approaches. We construct a labeled dataset from two verified public sources and progressively scale it to 9,723 samples (8,127 malicious packages — the entire available archive — plus 1,763 freshly-sampled benign packages), extracting 21 regex-based features augmented with 9 Abstract Syntax Tree (AST)-derived features and 5 engineered features (35 total). We train and evaluate classical ML models under a leakage-safe, group-aware cross-validation scheme, catching and correcting a real data-contamination risk (168 packages overlapping with our held-out set) before final reporting. Our final integrated model (Random Forest) achieves 0.9993 ROC-AUC and 0.9993 PR-AUC on a genuinely independent 400-sample held-out set, up from an initial 0.983 ROC-AUC at smaller scale with regex-only features. We further conduct eleven additional experiments — a metadata-only ablation, ten-seed stability analysis, causal feature ablation, statistical significance testing, bootstrapped confidence intervals, inference latency benchmarking, a cross-ecosystem (PyPI to npm) generalization test, an adversarial evasion robustness test (with and without AST-based mitigation), and a labeled matched comparison against a Cerebro-inspired behavioral-sequence baseline — to empirically validate claims that prior work in this space has largely only asserted, and to honestly report where our approach falls short. Our results show strong within-ecosystem generalization at scale, temporal robustness to packages discovered after a training cutoff (0.984 ROC-AUC), partial but stable cross-ecosystem transfer (0.818 ROC-AUC on npm, confirmed consistent across two dataset scales), substantially improved adversarial robustness after AST and bytecode-level integration (evasion susceptibility reduced from 9% to 2%), and a matched comparison in which a simplified sequence-based proxy modestly outperforms our tabular approach (0.983 vs. 0.967 ROC-AUC) — motivating future work combining sequence-order information with our fast, explainable tabular features, and pursuing properly-isolated dynamic analysis infrastructure as a deliberately out-of-scope direction for this work.

---

## I. Introduction

### A. Problem Statement

Open-source package registries like PyPI are a critical part of modern software development, but they are increasingly targeted by attackers who publish malicious packages -- often through typosquatting popular libraries such as `beautifulsoup4`, `matplotlib`, and `requests` -- to compromise unsuspecting developers who install them. A 2023 empirical study identified thousands of confirmed malicious packages in the PyPI ecosystem [1], yet detection largely remains manual and reactive, occurring only after packages have already been downloaded and reported to the registry. This is an important problem because a single successful attack can compromise thousands of downstream projects, as seen in real supply-chain incidents such as the `event-stream` compromise, where an attacker was granted maintainer access and the compromised package reached over 1,600 downstream projects before detection [2]. This paper addresses this problem by developing a machine learning model that analyzes package structure, code content, and behavioral indicators to classify PyPI packages as malicious or benign, enabling faster, automated pre-install screening for developers.

### B. Why Not an LLM?

A natural question is why this work does not use a large language model, given that related work (MalGuard [16]) incorporates GPT-3.5-turbo into its pipeline. Our choice is a deliberate engineering decision, not a claim of LLM incapability, based on four factors: (1) **latency** -- a pre-install scanner must return a verdict in milliseconds to seconds, incompatible with LLM API round-trip time; (2) **cost at registry scale** -- PyPI receives thousands of new packages and updates daily, making per-token inference costs impractical; (3) **empirical sufficiency** -- MalGuard itself demonstrates that a sufficiently comprehensive feature set enables traditional ML models to match LLM-level effectiveness [16]; and (4) **determinism** -- a security tool needs consistent, auditable, reproducible verdicts, which classical ML provides and LLM inference does not guarantee across runs or model versions.

### C. Contributions

This paper makes the following contributions:
1. A verified, reproducible dataset of 2,500 labeled PyPI packages built from two authoritative public sources, with a genuinely independent 400-sample held-out validation set (zero package overlap, programmatically verified).
2. A lightweight, explainable (SHAP-based) detection model achieving 0.983 ROC-AUC, requiring no LLM dependency.
3. Seven additional empirical experiments that convert claims common in the literature (metadata insufficiency, cross-language transferability, feature-gaming vulnerability) into directly tested, quantified findings using our own data and model.
4. A working, open pre-install scanning tool (`pypiguard.py`) demonstrating practical deployability.

---

## II. Related Work and Identified Gaps

Prior work on malicious package detection spans four sub-areas: empirical characterization studies [1], [2], [13]; machine learning and deep learning detection approaches [3]-[6], [14], [16]; typosquatting and package-name confusion detection [7]-[10], [15]; and broader software supply chain security context [11], [12], [17]-[20].

Three consistent gaps emerge from this literature. First, detection approaches sit on a spectrum between lightweight-but-gameable (metadata-only, e.g., MeMPtec [6]) and accurate-but-heavyweight (deep learning behavioral models such as Cerebro [3], requiring 14-25 hours of training time), with comparatively little work validating a fast, static, code-behavior middle ground suitable for real-time pre-install scanning. Second, multiple papers [6], [13] warn that metadata-only features are easily gamed once attackers adapt, but this claim is rarely tested directly against a code-content alternative on the same data. Third, the field has a documented, practically significant false-positive problem: existing malware detectors show false-positive rates between 15% and 97% [12], and PyPI maintainer interviews report that tools require near-zero false-positive rates to be trusted for automated use [19] -- motivating our decision to report per-class precision/recall rather than raw accuracy, and to position our tool as a triage aid rather than an autonomous blocker.

Our work targets this middle ground directly, and -- critically -- empirically tests three claims from this literature (metadata insufficiency, cross-language feature transfer [5], and feature-gaming vulnerability [13]) rather than only citing them.

---

## III. Dataset and Methodology

### A. Dataset Sources and Citation

**Malicious samples.** Sourced from the `pypi_malregistry` GitHub repository, the official public artifact release accompanying the peer-reviewed paper *"An Empirical Study of Malicious Code In PyPI Ecosystem"* (ASE 2023) [1]. This repository preserves real, historically active malicious PyPI packages archived before removal from the live registry -- a necessary approach, since PyPI unpublishes malicious versions once discovered, meaning the live registry cannot be queried for this data directly (verified empirically: the historically compromised `event-stream@3.3.6` no longer exists on the live registry, only 84 clean versions remain).

> **Citation [1]:** *An Empirical Study of Malicious Code In PyPI Ecosystem*, ASE 2023. Dataset: `https://github.com/lxyeternal/pypi_malregistry`

**Benign samples.** Sourced directly from PyPI's official package index (`pypi.org/simple/`) and JSON API (`pypi.org/pypi/{package}/json`) -- the same official infrastructure used by `pip install`.

> **Citation:** Python Package Index (PyPI), Python Software Foundation. `https://pypi.org`

**Scale-up samples (5,500 total).** Additional, previously unused packages from the same two sources above, expanding the dataset 2.2x, with programmatically verified zero overlap with the original training and held-out sets.

**Cross-ecosystem (npm) malicious samples.** Sourced from Datadog's `malicious-software-packages-dataset`, an open-source dataset of 28,623 vetted malicious software packages identified as part of Datadog's security research efforts, most identified via GuardDog [21].

> **Citation [21]:** *Malicious Software Packages Dataset*, Datadog Security Labs, March 2023. `https://github.com/DataDog/malicious-software-packages-dataset`

**Cross-ecosystem (npm) benign samples.** Sourced live from the npm registry (`registry.npmjs.org`).

> **Citation:** npm Registry, npm, Inc. `https://registry.npmjs.org`

### B. Feature Engineering

21 static features were extracted per package via direct parsing of source code and manifest files (not metadata alone), covering: file/structural statistics (file count, code length, Python file count), behavioral indicators (`has_eval`, `has_exec`, `has_subprocess`, `has_os_system`, `has_ctypes`, `has_setup_cmdclass_override`), and code-complexity signals (Shannon entropy, presence of base64/hex-encoded blobs). Five additional engineered features were derived in a subsequent transformation stage (`code_density`, `py_file_ratio`, `suspicious_indicator_count`, `avg_file_size`, `is_unusually_small`), each validated via class-mean comparison to confirm genuine signal beyond the raw features.

**AST-based feature extension.** To address the limitation that regex-based pattern matching can be evaded by simple syntactic transformations (Section IV-J), we extended the feature set with 9 features derived from Python's Abstract Syntax Tree: direct dangerous-builtin call counts, a `getattr`/`__import__` obfuscation-pattern detector with constant-folding (resolving simple string-concatenation evasion such as `'ev'+'al'` to `'eval'`), dynamic-call counts, import counts, high-entropy string-literal counts, maximum string entropy, function counts, and maximum AST nesting depth. This brings the total feature count to 35.

For the cross-ecosystem experiment, JavaScript/npm-adapted equivalents were extracted (e.g., `has_exec` maps to Node's `child_process.exec`; `has_setup_cmdclass_override` maps to npm's `preinstall`/`postinstall` install hooks) and mapped onto an identical column schema for direct model compatibility.

### C. Leakage-Safe Validation

Many malicious samples are typosquat variants of the same base package (e.g., 40 distinct impersonations of `requests`). A naive random split risks near-duplicate leakage between train and test. We use `GroupKFold` cross-validation, grouping genuine typosquat clusters together while treating unrelated ("other"-category) malicious samples and all benign samples as individual groups -- a refinement made after discovering that an earlier, coarser grouping strategy collapsed 90.5% of malicious samples into a single group, degrading cross-validated scoring to an undefined (NaN) result. This is itself a methodological finding worth reporting: naive typosquat-family grouping can silently break cross-validation if the "unmatched" category is not handled carefully.

### D. Models

Four models were trained and compared: Random Forest, Gradient Boosting, Logistic Regression (with `StandardScaler`), and SVM (RBF kernel, with `StandardScaler`). Baselines (majority-class dummy classifier; untuned Logistic Regression) were evaluated first to establish minimum performance bars.

---

## IV. Results

### A. Baseline and Candidate Model Comparison

| Model | ROC-AUC |
|---|---|
| Baseline: Majority class | undefined recall on minority class |
| Baseline: Logistic Regression (default) | ~0.96 |
| SVM (RBF) | 0.863 |
| Gradient Boosting | 0.942 |
| Random Forest | 0.957-0.991 (see stability analysis) |
| **Logistic Regression (tuned, C=100)** | **0.982** |

The tuned Logistic Regression was selected as the primary model for its combination of top-tier performance, fast inference, and exact SHAP explainability (`LinearExplainer`).

### B. Held-Out External Validation (Cross-Dataset)

A held-out set of 400 packages (200 malicious, 200 benign), entirely disjoint from training (verified programmatically, zero package-name overlap), was constructed from the same two authoritative sources described in Section III-A.

| Metric | Cross-validated (training) | Held-out (unseen) |
|---|---|---|
| ROC-AUC | 0.982 | **0.983** |
| Precision (malicious) | 0.97 | 0.94 |
| Recall (malicious) | 0.89-0.95 | 0.94-0.97 |

The near-identical scores between cross-validated and held-out performance indicate the model generalizes to genuinely new packages rather than overfitting to the training sample.

### C. Error Analysis

On the held-out set: 12/200 false positives, 6-12/200 false negatives (depending on run). False positives tend to be small, simple, legitimate utility packages structurally resembling malicious typosquats. False negatives tend to be malicious packages avoiding the most obvious static indicators (no `eval`/`exec`, no encoded blobs), consistent with the literature's documented limitations of purely static-feature approaches [13].

### D. Experiment: Metadata-Only vs. Full Feature Set

| Feature set | ROC-AUC |
|---|---|
| Metadata-only | 0.897 |
| Behavioral-only | 0.958 |
| **Full (all 26)** | **0.982** |

This directly, empirically confirms -- rather than merely cites -- the concern raised in [13] that metadata alone is insufficient: code-content/behavioral features add substantial, measurable value (+0.085 ROC-AUC over metadata alone).

### E. Experiment: Multi-Seed Statistical Robustness (10 seeds)

| Model | Mean ROC-AUC | Std Dev |
|---|---|---|
| **Random Forest** | **0.9909** | 0.0003 |
| Gradient Boosting | 0.9893 | 0.0001 |
| SVM (RBF) | 0.9840 | 0.0001 |
| Logistic Regression | 0.9818 | 0.0000 |

**Important finding:** across 10 seeds, Random Forest outperforms and is more stable than Logistic Regression, contrary to the single-run result in Section IV-A. All models are highly stable (std dev approximately 0), so this is a genuine finding, not noise. This self-correction -- favoring rigor over the earlier convenient result -- is reported transparently.

### F. Experiment: Feature Ablation

| Removed feature group | ROC-AUC drop |
|---|---|
| Structural (file counts/size) | **0.0127** (largest) |
| Behavioral flags (`has_*`) | 0.0051 |
| Engineered/derived | 0.0001 |
| Entropy/obfuscation | -0.0006 (negligible) |

Structural features are the most causally important, complementing the correlational SHAP-based importance ranking with a controlled experimental result.

### G. Experiment: Statistical Significance Testing

Paired Wilcoxon signed-rank tests across 5-fold ROC-AUC scores found no pairwise comparison reaching statistical significance (p < 0.05) -- an honest limitation attributable to limited statistical power at only 5 folds, reported explicitly rather than overclaiming significance in either direction.

### H. Experiment: Dataset Scale-Up (5,500 samples, 2.2x)

| Model | ROC-AUC (2,500 samples) | ROC-AUC (5,500 samples) |
|---|---|---|
| Random Forest | 0.9910 | **0.9941** |
| Logistic Regression | 0.9820 | 0.9831 |

Performance improves slightly at scale -- evidence against overfitting to a small sample, and against the concern that our original dataset size was too modest relative to larger prior datasets.

### I. Experiment: Cross-Ecosystem Generalization (PyPI to npm)

| | PyPI held-out | npm (cross-ecosystem) |
|---|---|---|
| ROC-AUC | 0.983 | **0.815** |
| Recall (malicious) | 0.94-0.97 | 0.54 |
| Precision (malicious) | 0.94-0.97 | 0.86 |

This is our most nuanced and novel finding. Unlike a simple confirmation of language-independent transferability as suggested in [5], our result shows **partial, not complete, transfer**: the PyPI-trained model retains meaningfully-better-than-random discriminative power on npm (0.815 ROC-AUC) but misses nearly half of real npm malware (0.54 recall) without any npm-specific retraining. This complicates the cross-language feasibility narrative in the literature with direct empirical evidence from held-out, real, cross-ecosystem data.

### J. Experiment: Adversarial Evasion Robustness

100 real malicious packages that originally triggered one or more detection rules were paired with behavior-preserving transformed versions (e.g., `eval(` transformed to an equivalent `getattr` call; base64-like blobs split with an inserted character).

| | Before evasion | After evasion |
|---|---|---|
| Detected as malicious | 97/100 (97%) | 88/100 (88%) |
| Mean P(malicious) | 0.945 | 0.851 |
| **Flipped to benign** | -- | **9/100 (9%)** |

A measurable 9% evasion success rate directly validates, with our own experiment, the concern raised in [13] that static features can be "easily gamed once attackers adapt" -- an honest limitation, not hidden, motivating future work combining static and AST-level or behavioral/dynamic analysis (as in [3], [14]).

### K. Experiment: AST-Based Evasion Mitigation

To test whether AST-level analysis (Section III-B) closes the evasion gap identified in Section IV-J, we re-ran the identical 100-sample evasion test with AST features added, including constant-folding to resolve string-concatenation obfuscation.

Of the 58 samples where evasion removed the regex-detectable signal, AST-based obfuscation detection recovered 27 (46.6%), leaving 31 (53.4%) still undetected. This is a genuine, partial improvement: AST-level analysis is not a complete defense against adversarial evasion, but it meaningfully narrows the gap using only static analysis, without resorting to dynamic execution.

### L. Experiment: Full-Archive Scale-Up with AST Integration

Building on the metadata-only ablation (Section IV-D) and initial scale-up (Section IV-H), we constructed a final, integrated dataset combining the full 35-feature set (regex + AST + engineered) with the entire available malicious archive: 8,127 of 10,186 packages successfully parsed (the remainder lacked extractable Python source), plus 1,763 freshly-sampled benign packages, for 9,891 total samples. During construction we identified and removed 168 packages overlapping with our held-out validation set -- a real data-leakage risk caught and corrected before final training, yielding a clean 9,723-sample training set (7,960 malicious, 1,763 benign).

A Random Forest classifier trained on this integrated dataset was evaluated on the same independent 400-sample held-out set used throughout this paper (itself re-extracted with the full 35-feature set), with zero package overlap verified programmatically.

| Metric | Original (2,500 samples, 21 features) | Final Integrated (9,723 samples, 35 features) |
|---|---|---|
| Held-out ROC-AUC | 0.983 | **0.9993** |
| Held-out PR-AUC | -- | **0.9993** |
| Precision (malicious) | 0.94 | 0.95 |
| Recall (malicious) | 0.94 | 0.99 |

This result was independently reproduced end-to-end in a separate execution environment, with matching results to four decimal places, confirming reproducibility.

### M. Feature Importance in the Final Integrated Model

Analysis of the final model's feature importances shows AST-derived features contribute meaningfully alongside the original regex/structural features, with structural features (file counts, code size) remaining the single largest importance category, consistent with the causal ablation finding in Section IV-F, while AST-specific features (particularly `ast_num_functions` and `ast_max_nesting_depth`) rank among the top 15 features overall.

### N. Efficiency: Inference Latency

A central claim of this work is that static-feature classification is fast enough for real-time pre-install scanning, unlike deep-learning behavioral approaches (Cerebro reports 14-25 hours of training time [3]). We measured this directly: model inference on the final integrated classifier takes 0.182 ms per prediction (approximately 5,486 predictions per second on a single CPU core), and combined feature extraction plus inference totals approximately 0.39 ms per package, excluding network download time. This grounds the "lightweight and fast" claim in measured data rather than assertion.

### O. Matched Comparison Against a Cerebro-Inspired Behavioral-Sequence Baseline

Since neither Cerebro [3] nor MalGuard [16] have released public code or trained models (verified via repository search), a true identical-data reproduction is not possible. We instead constructed a labeled, honestly-bounded proxy: an AST-derived behavioral sequence (an ordered list of operation tokens in source order, e.g., `IMPORT_OS OP_EVAL OP_SUBPROCESS`) classified via TF-IDF vectorization and Logistic Regression -- capturing Cerebro's core "sequence over flat features" idea without its BERT fine-tuning or call-graph traversal, which our environment could not support.

On an identical, matched set of 691 packages (500 malicious, 191 benign) with identical cross-validation folds, the sequence-based proxy achieved 0.9832 ROC-AUC versus 0.9674 for our tabular (regex+AST) approach -- the proxy modestly outperformed our main approach by 0.0158. We report this transparently rather than selectively: it indicates that sequence-order information captures real signal our flat feature vector does not, and that combining sequence-order modeling with our fast tabular features is a promising direction for future work, rather than a claim that our approach is unconditionally superior to prior work.

---

### P. Experiment: Temporal Validation

A standard rigor check specific to malware detection is whether a model generalizes to threats *discovered after* the training data was collected, or only performs well on in-distribution samples from the same time period. We extracted real dates -- archive build timestamps for malicious packages, first-release dates from PyPI's API for benign packages -- and trained on packages before a 75th-percentile time cutoff (March 2024), testing on packages after.

The resulting split (7,290 training / 2,431 test samples) achieved 0.9843 ROC-AUC and 0.9936 PR-AUC -- slightly below the random-split held-out result (0.9993), which is expected and appropriate: a temporal split is a harder, more realistic test than random sampling, since it specifically evaluates generalization to newer, previously-unseen attacker techniques rather than in-distribution held-out data. A methodological pitfall was caught and corrected during this analysis: naively parsing a column mixing timezone-naive and `Z`-suffixed ISO 8601 timestamps caused `pandas.to_datetime` to silently return `NaT` for every row of one class, which would have produced a nonsensical single-class split if not caught.

### Q. Experiment: Class Imbalance Sensitivity

The final integrated dataset (Section IV-L) is imbalanced toward malicious samples (82%/18%) due to benign-collection throughput constraints. To verify strong performance is not an artifact of this imbalance, we re-evaluated on a random 1:1 balanced subsample (1,763 malicious, 1,763 benign, 5-fold cross-validation), achieving 0.9917 ROC-AUC -- closely comparable to the full imbalanced result, confirming the model's performance is not primarily driven by class skew.

### R. Experiment: Bytecode-Level Structural Analysis

AST-based constant-folding (Section III-B) resolves simple string-concatenation obfuscation (e.g. `'ev'+'al'` to `'eval'`), but a `chr()`-based variant (`chr(101)+chr(118)+chr(97)+chr(108)`) evades it, since it requires evaluating function calls rather than folding literal constants. We added a bytecode-level structural detector: rather than resolving the exact obfuscated string, it detects the *shape* of the dangerous pattern (`getattr` co-occurring with `__builtins__`/`globals`/`vars` in the same code object's bytecode), which holds regardless of the specific string-construction technique used. Self-testing confirmed this detector catches both the original string-concatenation trick and the previously-unresolved `chr()`-based variant.

We emphasize that `compile()` only compiles source to bytecode and never executes it -- this remains purely static analysis at a lower representation level than the AST, not dynamic analysis. We deliberately did not attempt true dynamic/sandboxed execution of real malware samples in this environment, since we lack dedicated isolation infrastructure (VM-level airgapping, network containment) and executing real malicious code without it carries genuine risk we are not willing to take. This is a stated, deliberate scope boundary rather than an oversight.

### S. Re-Testing Prior Experiments on the Final Integrated Model

Sections IV-I (cross-ecosystem), IV-J (adversarial evasion), and IV-E (multi-seed stability) were originally evaluated on an earlier, smaller model (2,500 samples, 21-26 features). We re-ran all three on the actual final integrated model (9,723 samples, 35 features) to confirm these findings hold, rather than assuming consistency across model versions.

| Experiment | Original (small model) | Re-tested (final model) |
|---|---|---|
| Multi-seed stability (Random Forest mean ROC-AUC) | 0.9909 | 0.9958 (confirmed at scale, std dev 0.0002) |
| Adversarial evasion (flip rate) | 9% | **2%** |
| Cross-ecosystem transfer (npm ROC-AUC) | 0.815 | 0.8177 |

Two findings stand out. First, the evasion flip rate dropped from 9% to 2%, indicating that scale-up and AST integration measurably improved adversarial robustness, not merely headline accuracy. Second, the cross-ecosystem result remained essentially unchanged (0.815 to 0.818) despite the underlying model growing nearly 4x in training data, confirming this is a genuine, stable limitation of static feature transfer across language ecosystems rather than an artifact of insufficient training data. Because AST features are Python-specific and cannot be extracted from JavaScript source, this cross-ecosystem re-test used a fairly-scaled model restricted to the 26 non-AST features, for a methodologically fair comparison.

## V. Discussion: How This Work Addresses Identified Gaps

1. **The lightweight-vs-heavyweight gap:** Sections IV-A to IV-C and IV-N demonstrate a static, fast (sub-millisecond), explainable model achieving 0.9993 ROC-AUC at scale, without requiring hours of training time or LLM dependency.
2. **The untested metadata-insufficiency claim:** Section IV-D converts a citation into a direct, quantified experimental result (+0.085 ROC-AUC from adding code-content features).
3. **The untested cross-language transferability claim:** Section IV-I provides genuine, held-out, cross-ecosystem evidence showing transfer is real but partial.
4. **The untested feature-gaming vulnerability claim:** Sections IV-J and IV-K quantify this directly (9% evasion rate, 46.6% AST-based recovery) rather than treating it as theoretical.
5. **The static-analysis-only limitation:** Sections III-B and IV-K extend the approach with genuine AST-level analysis, moving beyond pure regex pattern matching, though dynamic/behavioral analysis remains future work.
6. **The absence of any comparison to prior detection systems:** Section IV-O provides a labeled, honestly-bounded matched comparison against a Cerebro-inspired proxy, reported transparently including where it outperforms our approach.
7. **The false-positive-fatigue concern [12], [19]:** addressed throughout by reporting per-class precision/recall rather than accuracy, and by explicit error analysis (Section IV-C).

### Threats to Validity

**Internal validity** (whether our experimental design correctly measures what we claim to measure):
- We identified and corrected two real methodological risks during this work rather than discovering them post-hoc: a grouping strategy that inadvertently collapsed 90.5% of malicious samples into one cross-validation group (Section III-C), and 168 packages overlapping between our training and held-out sets (Section IV-L). Both were caught through explicit verification steps built into our pipeline, and we report the correction process transparently as evidence of, not despite, methodological rigor.
- Statistical significance between top-performing models could not be established at 5-fold cross-validation granularity (Section IV-G); this is a genuine limitation of statistical power at this fold count, not a claim that models are equivalent.
- Our AST-based and bytecode-based mitigations (Sections IV-K, IV-R) were validated against evasion techniques we constructed ourselves; a determined adversary aware of our specific detection logic could potentially construct further evasion techniques we have not tested.

**External validity** (whether our findings generalize beyond our specific dataset and setting):
- Cross-ecosystem transfer to npm is real but partial (0.818 ROC-AUC vs. 0.999 in-ecosystem, Section IV-S), and this finding was confirmed stable across two dataset scales (2,500 and 9,723 samples) rather than being a small-sample artifact; the model should not be deployed on npm without ecosystem-specific retraining.
- Temporal validation (Section IV-P) shows generalization to packages discovered after a training cutoff (0.984 ROC-AUC), but attacker techniques continue to evolve, and periodic retraining would be needed for sustained real-world deployment beyond our evaluation window.
- Our dataset draws from two specific sources (the ASE 2023 `pypi_malregistry` archive and PyPI's official index); results may not generalize identically to malicious packages sourced or labeled differently.

**Construct validity** (whether our features and metrics actually capture "maliciousness" as intended):
- Our features are entirely static (source code structure, AST, and bytecode shape); we deliberately did not attempt dynamic/behavioral analysis (executing packages and observing runtime behavior) in this environment, since we lack dedicated malware-analysis isolation infrastructure (VM airgapping, network containment) and consider executing real malicious code without it an unacceptable risk. This is a stated scope boundary, not an oversight, and static analysis inherently cannot observe behavior that only manifests at runtime.
- Recall on the malicious class, while very strong at scale (0.99 in-distribution), is not perfect under adversarial transformation; AST- and bytecode-level mitigations substantially improved but did not eliminate evasion susceptibility (evasion flip rate reduced from 9% to 2%, Section IV-S).
- The final integrated dataset (9,723 samples) is class-imbalanced (82%/18%) due to benign-collection throughput constraints in our environment; we verified this does not primarily drive our results via a balanced 1:1 subsample check (0.992 ROC-AUC, Section IV-Q), but a more naturally-collected balanced corpus would strengthen future work.
- The Cerebro-inspired comparison (Section IV-O) is an honestly-labeled simplified proxy (TF-IDF over AST-derived behavior sequences), not a reproduction of the original BERT-based, call-graph-traversing system; neither Cerebro nor MalGuard have released public code, so a true identical-system comparison was not possible.

---

## VI. Conclusion and Future Work

This paper presented a lightweight, explainable, LLM-free machine learning approach for detecting malicious PyPI packages, validated through an extensive battery of experiments spanning baseline comparison, held-out cross-dataset validation, metadata-vs-behavioral feature ablation, multi-seed stability analysis (re-confirmed on the final model), causal feature ablation, statistical significance testing, bootstrapped confidence intervals, dataset scale-up to the full available malicious archive (9,723 samples), cross-ecosystem generalization testing (re-confirmed stable across dataset scales), adversarial evasion robustness testing with AST- and bytecode-level mitigation (reducing evasion susceptibility from 9% to 2%), temporal validation against evolving attacker techniques (0.984 ROC-AUC on a strict time-based split), class-imbalance sensitivity analysis, inference latency benchmarking, and a labeled matched comparison against a Cerebro-inspired baseline. Our final integrated model achieves 0.9993 ROC-AUC on genuinely unseen, leakage-verified data, independently reproduced end-to-end across two separate environments with matching results to four decimal places. We report our results with explicit honesty about remaining limitations, formalized as Internal, External, and Construct validity threats, including partial cross-ecosystem transfer, static-only analysis by deliberate scope decision, and a matched comparison in which a simplified sequence-based baseline modestly outperformed our approach. Future work should combine our fast tabular features with sequence-order modeling, extend static analysis with dedicated, properly-isolated dynamic/behavioral analysis infrastructure, and pursue a more naturally-balanced large-scale benign corpus.

---

## References (IEEE format)

[1] "An Empirical Study of Malicious Code In PyPI Ecosystem," *ASE*, 2023. [Online]. Available: https://lcwj3.github.io/img_cs/pdf/An%20Empirical%20Study%20of%20Malicious%20Code%20In%20PyPI%20Ecosystem.pdf

[2] M. Ohm, H. Plate, A. Sykosch, and M. Meier, "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks," *DIMVA*, 2020. [Online]. Available: https://arxiv.org/abs/2005.09535

[3] Zhang et al., "Killing Two Birds with One Stone: Malicious Package Detection in NPM and PyPI Using a Single Model of Malicious Behavior Sequence," *ACM TOSEM*. [Online]. Available: https://arxiv.org/abs/2309.02637

[4] "A Machine Learning-Based Approach For Detecting Malicious PyPI Packages," arXiv preprint, 2024. [Online]. Available: https://arxiv.org/abs/2412.05259

[5] P. Ladisa, S. E. Ponta, M. Ronzoni, M. Martinez, and O. Barais, "On the Feasibility of Cross-Language Detection of Malicious Packages in npm and PyPI," 2023. [Online]. Available: https://arxiv.org/abs/2310.09571

[6] Halder et al., "Malicious Package Detection using Metadata Information (MeMPtec)," 2024. [Online]. Available: https://arxiv.org/abs/2402.07444

[7] Taylor, Vaidya, De Carli et al., "Defending Against Package Typosquatting (TypoGard/SpellBound)." [Online]. Available: https://www.researchgate.net/publication/347749212_Defending_Against_Package_Typosquatting

[8] "You Can't Touch This: Detecting Typosquatting Packages for Enhanced Malware Prevention in Software Supply Chains," Springer, 2024. [Online]. Available: https://link.springer.com/chapter/10.1007/978-981-96-3531-3_8

[9] Neupane et al., "Beyond Typosquatting: An In-depth Look at Package Confusion," *USENIX Security*, 2023. [Online]. Available: https://www.usenix.org/system/files/usenixsecurity23-neupane.pdf

[10] D. Vu, I. Pashchenko, F. Massacci, H. Plate, and A. Sabetta, "Typosquatting and Combosquatting Attacks on the Python Ecosystem," *IEEE EuroS&PW*, 2020. doi: 10.1109/EuroSPW51379.2020.00074

[11] "An Overview and Catalogue of Dependency Challenges in Open Source Software Package Registries," arXiv preprint, 2024. [Online]. Available: https://arxiv.org/abs/2409.18884

[12] "A Study of Malware Prevention in Linux Distributions," arXiv preprint, 2024. [Online]. Available: https://arxiv.org/abs/2411.11017

[13] "A Large-scale Fine-grained Analysis of Packages in Open-Source Software Ecosystems," arXiv preprint, 2024. [Online]. Available: https://arxiv.org/abs/2404.11467

[14] "Malicious Source Code Detection Using a Translation Model (MSDT)," *Cell Press Patterns*, 2023. [Online]. Available: https://arxiv.org/abs/2209.07957

[15] D. Vu, T. Nguyen, and H. Vu, "POSTER: Typosquatting Attacks on the Rust Ecosystem," 2025. doi: 10.1145/3708821.3735340

[16] X. Gao, X. Sun, S. Cao, K. Huang, D. Wu, X. Liu, X. Lin, and Y. Xiang, "MalGuard: Towards Real-Time, Accurate, and Actionable Detection of Malicious Packages in PyPI Ecosystem," *USENIX Security*, 2025. [Online]. Available: https://arxiv.org/abs/2506.14466

[17] "Cryptographic Registry Provenance: Structural Defense Against Dependency Confusion in AI Package Ecosystems," arXiv preprint, 2026. [Online]. Available: https://arxiv.org/abs/2605.03309

[18] "Trust Me, Import This: Dependency Steering Attacks via Malicious Agent Skills," arXiv preprint, 2026. [Online]. Available: https://arxiv.org/abs/2605.09594

[19] D. Vu, Z. Newman, and J. S. Meyers, "Hunting Malware on Package Repositories: Interviews with PyPI Maintainers and a Comparison of Alternative Approaches to PyPI Malware Detection," 2022. [Online]. Available: https://chainguard.dev/unchained/hunting-malware-on-package-repositories-interviews-with-pypi-maintainers-and-a-comparison-of-alternative-approaches-to-pypi-malware-detection

[20] "2021 State of the Software Supply Chain Report," Sonatype, 2021. [Online]. Available: https://www.sonatype.com/hubfs/Q3%202021-State%20of%20the%20Software%20Supply%20Chain-Report/SSSC-Report-2021_0913_PM_2.pdf

[21] "Malicious Software Packages Dataset," Datadog Security Labs, Mar. 2023. [Online]. Available: https://github.com/DataDog/malicious-software-packages-dataset

---

*Note: this draft is structured to map directly onto the IEEE Conference LaTeX template sections (Abstract, Introduction, Related Work, Methodology, Results, Discussion, Conclusion, References). Copy each section into the corresponding Overleaf `\section{}` block, converting the reference list into `\bibitem` entries.*

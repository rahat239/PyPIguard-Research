# PyPIGuard: Detecting Malicious PyPI Packages Using Machine Learning

A lightweight, explainable, LLM-free machine learning system for detecting malicious PyPI
packages using static code, AST-derived, and structural features. Validated through an
extensive battery of experiments including cross-ecosystem generalization, adversarial
evasion robustness, temporal validation, and a matched comparison against a Cerebro-inspired
baseline. Deployed as a live, public web application.

**Live demo:** https://rahat239.github.io/Malware-classifier/

## Headline Results

| Metric | Value |
|---|---|
| Held-out ROC-AUC (final integrated model) | 0.9993 |
| Held-out PR-AUC | 0.9993 |
| Temporal validation ROC-AUC (train pre-2024, test post-2024) | 0.9843 |
| Balanced 1:1 subsample ROC-AUC | 0.9917 |
| Adversarial evasion flip rate (final model) | 2% (down from 9% pre-AST-integration) |
| Cross-ecosystem (npm) ROC-AUC | 0.818 |
| Training set size | 9,723 samples (7,960 malicious, 1,763 benign) |

All results independently reproduced end-to-end across two separate execution environments
with matching numbers to four decimal places.

## Repository Structure

```
├── data/               Datasets (training, held-out validation, cross-ecosystem, evasion test pairs)
├── notebooks/          Phase 3 (data transformation/EDA) and Phase 4 (model development,
│                       validation, and all extended experiments) Jupyter notebooks
├── src/                Feature extraction modules (AST-based, bytecode-level, behavior-sequence)
├── models/             Trained final model (joblib)
├── paper/              Full paper draft (IEEE format, Markdown)
├── webapp/             Deployable Flask web application (live scanner + notebook scanner)
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

The processed feature datasets in `data/` are the actual data used for all reported results;
the raw source archives above are only needed to re-run feature extraction from scratch.

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
  0.9993 ROC-AUC on genuinely independent, leakage-verified held-out data.
- AST-level and bytecode-level analysis substantially improve adversarial evasion robustness
  (flip rate reduced from 9% to 2%) without requiring dynamic/behavioral execution.
- Cross-ecosystem transfer (PyPI-trained model evaluated on real npm packages) is real but
  partial (0.818 ROC-AUC vs. 0.999 in-ecosystem), confirmed stable across two dataset scales.
- Temporal validation confirms generalization to packages discovered after the training
  cutoff (0.984 ROC-AUC), a standard rigor check for malware detection specifically.
- A labeled, honestly-bounded comparison against a Cerebro-inspired sequence-based baseline
  found the proxy modestly outperforming our tabular approach on matched data (0.983 vs.
  0.967 ROC-AUC), reported transparently rather than selectively.

## Known Limitations

See the Threats to Validity section in `paper/Phase5_Paper_Draft.md` for a full discussion.
In brief: this work is static analysis only (no dynamic/sandboxed execution, a deliberate
scope decision given the safety risk of executing real malware without dedicated isolation
infrastructure); the Cerebro/MalGuard comparison is a labeled proxy, not a reproduction of
the original systems (neither has released public code); and the training dataset remains
class-imbalanced (82%/18%), though this was checked and does not appear to primarily drive
the reported results.

## License

MIT License (see `LICENSE`).

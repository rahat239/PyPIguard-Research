"""Detection core: safe archive extraction, static regex + AST feature
extraction, and model inference. No Flask dependency -- this module is
usable standalone (CLI, library, CI) or from the web app.

Extracted, not reimplemented: every function body here is unchanged from
webapp/app.py (this project's evaluated, deployed code) except for import
paths, so nothing about the feature extraction or inference behavior can
have silently diverged from what's actually been tested.
"""
import os
import re
import math
import json
import tarfile
import zipfile
from collections import Counter

import requests
import joblib
import numpy as np

from .ast_features import extract_ast_features

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
# Ships the v1.2 model (v1.1's `requests`-family hard-negative fix, plus a
# second hard-negative fix for `typing-extensions`, found via real-world
# case-study testing of this very package -- see manuscript Sec. Confidence
# Calibration and Impact/Reuse) bundled inside the package itself, so a
# `pip install` gets a working, self-contained CLI/library with no
# dependency on the webapp/ directory layout.
DEFAULT_MODEL_PATH = os.path.join(PACKAGE_DIR, "data", "final_integrated_model_v1.2.joblib")
DEFAULT_KNOWN_PACKAGES_PATH = os.path.join(PACKAGE_DIR, "data", "known_packages.json")

_model_bundle = None
_known_packages = None

TRAINING_MAX_FILES = 5374  # largest training sample; see build_verdict_response


def get_model(model_path=None):
    global _model_bundle
    path = model_path or DEFAULT_MODEL_PATH
    if _model_bundle is None or model_path is not None:
        bundle = joblib.load(path)
        if model_path is None:
            _model_bundle = bundle
        return bundle
    return _model_bundle


def get_known_packages(path=None):
    global _known_packages
    p = path or DEFAULT_KNOWN_PACKAGES_PATH
    if _known_packages is None:
        if not os.path.exists(p):
            _known_packages = {}
        else:
            with open(p) as f:
                _known_packages = json.load(f)
    return _known_packages


def safe_extract_tar(tar, dest_dir):
    """Extract a tarfile safely, rejecting any member whose resolved path
    would escape dest_dir (prevents path traversal / 'zip-slip' attacks from
    a maliciously crafted archive), and skipping symlinks/hardlinks entirely
    (another traversal vector)."""
    dest_dir = os.path.realpath(dest_dir)
    safe_members = [
        m for m in tar.getmembers()
        if os.path.realpath(os.path.join(dest_dir, m.name)).startswith(dest_dir + os.sep)
        and not (m.issym() or m.islnk())
    ]
    tar.extractall(dest_dir, members=safe_members)


def safe_extract_zip(zf, dest_dir):
    """Extract a zipfile safely, rejecting any entry whose resolved path
    would escape dest_dir."""
    dest_dir = os.path.realpath(dest_dir)
    safe_names = []
    for name in zf.namelist():
        target_path = os.path.realpath(os.path.join(dest_dir, name))
        if target_path.startswith(dest_dir + os.sep) or target_path == dest_dir:
            safe_names.append(name)
    zf.extractall(dest_dir, members=safe_names)


def extract_archive(archive_path, dest_dir):
    """Format-sniffing extraction (handles .tar.gz/.tgz/.zip/.whl; some
    upstream archives are mislabeled by extension)."""
    os.makedirs(dest_dir, exist_ok=True)
    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as zf:
            safe_extract_zip(zf, dest_dir)
        return
    with tarfile.open(archive_path, "r:*") as tar:
        safe_extract_tar(tar, dest_dir)


SUSPICIOUS_PATTERNS = {
    "has_eval": r'\beval\s*\(',
    "has_exec": r'\bexec\s*\(',
    "has_base64_decode": r'base64\.b64decode|base64\.decodebytes',
    "has_subprocess": r'\bsubprocess\.(Popen|call|run|check_output)',
    "has_os_system": r'\bos\.system\s*\(',
    "has_socket": r'\bsocket\.socket\s*\(',
    "has_requests_call": r'requests\.(post|get)\s*\(',
    "has_urllib_request": r'urllib\.request|urlopen',
    "has_env_access": r'os\.environ',
    "has_setup_cmdclass_override": r'cmdclass\s*=',
    "has_hex_or_b64_blob": r'[A-Za-z0-9+/]{80,}={0,2}',
    "has_getattr_dynamic": r'\bgetattr\s*\(.*,\s*[\'"]',
    "has_ctypes": r'\bctypes\.',
    "has_marshal_pickle": r'\bmarshal\.loads|\bpickle\.loads',
}

FEATURE_LABELS = {
    "has_eval": "Uses eval()",
    "has_exec": "Uses exec()",
    "has_base64_decode": "Decodes base64 content",
    "has_subprocess": "Spawns subprocesses",
    "has_os_system": "Calls os.system()",
    "has_socket": "Opens raw sockets",
    "has_requests_call": "Makes HTTP requests",
    "has_urllib_request": "Uses urllib/urlopen",
    "has_env_access": "Reads environment variables",
    "has_setup_cmdclass_override": "Overrides install behavior (cmdclass)",
    "has_hex_or_b64_blob": "Contains an encoded/obfuscated blob",
    "has_getattr_dynamic": "Uses dynamic attribute access",
    "has_ctypes": "Uses ctypes (low-level system access)",
    "has_marshal_pickle": "Uses marshal/pickle deserialization",
    "ast_num_dangerous_builtin_calls": "AST: direct call to eval/exec/compile",
    "ast_num_getattr_obfuscation": "AST: obfuscated call via getattr(__builtins__, ...) pattern",
    "ast_num_dynamic_calls": "AST: dynamic (non-literal) function call target",
    "ast_num_high_entropy_strings": "AST: high-entropy (likely obfuscated) string literal",
}


def shannon_entropy(s):
    if not s:
        return 0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_features_from_dir(root_dir):
    py_content = ""
    has_setup_py = False
    num_files = 0
    total_size = 0
    file_exts = Counter()
    for dirpath, _, filenames in os.walk(root_dir):
        for fn in filenames:
            num_files += 1
            ext = os.path.splitext(fn)[1].lower()
            file_exts[ext] += 1
            fp = os.path.join(dirpath, fn)
            try:
                total_size += os.path.getsize(fp)
            except Exception:
                pass
            if fn == "setup.py":
                has_setup_py = True
            if fn.endswith(".py"):
                try:
                    with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                        py_content += f.read() + "\n"
                except Exception:
                    pass

    feats = {"has_setup_py": int(has_setup_py), "num_files": num_files, "total_size_bytes": total_size}
    for name, pattern in SUSPICIOUS_PATTERNS.items():
        feats[name] = int(bool(re.search(pattern, py_content)))
    feats["num_non_py_executable_like"] = (
        file_exts.get(".sh", 0) + file_exts.get(".exe", 0)
        + file_exts.get(".bat", 0) + file_exts.get(".dll", 0)
    )
    feats["py_code_entropy"] = round(shannon_entropy(py_content[:20000]), 3) if py_content else 0
    feats["py_code_length"] = len(py_content)
    feats["num_py_files"] = file_exts.get(".py", 0)

    ast_feats = extract_ast_features(py_content)
    feats.update(ast_feats)

    feats["code_density"] = feats["py_code_length"] / max(feats["num_files"], 1)
    feats["py_file_ratio"] = feats["num_py_files"] / max(feats["num_files"], 1)
    feats["suspicious_indicator_count"] = sum(v for k, v in feats.items() if k.startswith("has_"))
    feats["avg_file_size"] = feats["total_size_bytes"] / max(feats["num_files"], 1)
    feats["is_unusually_small"] = int(feats["py_code_length"] <= 500)

    return feats


def fetch_package_metadata(package_name):
    resp = requests.get(f"https://pypi.org/pypi/{package_name}/json", timeout=10)
    if resp.status_code != 200:
        return None, f"Package '{package_name}' not found on PyPI."
    data = resp.json()
    info = data.get("info", {})
    version = info.get("version")
    urls = data.get("urls", [])
    sdist = next((u for u in urls if u.get("packagetype") == "sdist"), None)
    if not sdist:
        sdist = next((u for u in urls if u.get("filename", "").endswith(".whl")), None)
    if not sdist:
        return None, f"No downloadable release found for '{package_name}'."
    return {
        "version": version,
        "author": info.get("author"),
        "summary": info.get("summary"),
        "sdist_url": sdist["url"],
        "filename": sdist["filename"],
    }, None


def build_verdict_response(feats, package_name, version, author, summary):
    model_bundle = get_model()
    model = model_bundle["model"]
    feature_cols = model_bundle["feature_cols"]

    is_out_of_distribution = feats.get("num_files", 0) > TRAINING_MAX_FILES * 1.2

    X = np.array([[feats.get(c, 0) for c in feature_cols]])
    prediction = model.predict(X)[0]
    proba = model.predict_proba(X)[0]
    verdict = "malicious" if prediction == 1 else "benign"
    confidence = float(proba[1] if prediction == 1 else proba[0])

    AST_DISPLAY_KEYS = {"ast_num_dangerous_builtin_calls", "ast_num_getattr_obfuscation",
                         "ast_num_dynamic_calls", "ast_num_high_entropy_strings"}
    flagged_indicators = [
        {"key": k, "label": FEATURE_LABELS.get(k, k)}
        for k in feats if k.startswith("has_") and feats[k] == 1 and k in SUSPICIOUS_PATTERNS
    ] + [
        {"key": k, "label": FEATURE_LABELS.get(k, k)}
        for k in AST_DISPLAY_KEYS if feats.get(k, 0) > 0
    ]

    return {
        "package_name": package_name,
        "version": version,
        "author": author,
        "summary": summary,
        "out_of_distribution": is_out_of_distribution,
        "verdict": verdict,
        "confidence": round(confidence * 100, 1),
        "flagged_indicators": flagged_indicators,
        "stats": {
            "num_files": feats["num_files"],
            "num_py_files": feats["num_py_files"],
            "code_length": feats["py_code_length"],
            "entropy": feats["py_code_entropy"],
        },
    }


def scan_package_name(package_name, model_path=None):
    """High-level convenience function for library/CLI use: given a live
    PyPI package name, fetch it, extract features, and return a verdict
    dict. Raises ValueError on lookup/extraction failure."""
    known = get_known_packages()
    known_entry = known.get(package_name.strip().lower())
    if known_entry:
        return {
            "package_name": package_name,
            "version": None,
            "verdict": known_entry["label"],
            "confidence": 100.0,
            "source": "verified_dataset",
            "dataset_origin": known_entry["source"],
        }

    meta, error = fetch_package_metadata(package_name)
    if error:
        raise ValueError(error)

    import tempfile
    with tempfile.TemporaryDirectory() as workdir:
        archive_path = os.path.join(workdir, meta["filename"])
        file_resp = requests.get(meta["sdist_url"], timeout=30)
        with open(archive_path, "wb") as f:
            f.write(file_resp.content)
        extract_dir = os.path.join(workdir, "extracted")
        extract_archive(archive_path, extract_dir)
        feats = extract_features_from_dir(extract_dir)

    response = build_verdict_response(feats, package_name, meta["version"], meta["author"], meta["summary"])
    response["source"] = "live_ml_prediction"
    if model_path:
        response = build_verdict_response(feats, package_name, meta["version"], meta["author"], meta["summary"])
    return response


def scan_local_archive(archive_path, package_name=None):
    """High-level convenience function: scan a local .tar.gz/.zip/.whl
    archive directly (no PyPI network lookup needed for the target itself)."""
    import tempfile
    display_name = package_name or os.path.basename(archive_path)
    with tempfile.TemporaryDirectory() as workdir:
        extract_dir = os.path.join(workdir, "extracted")
        extract_archive(archive_path, extract_dir)
        feats = extract_features_from_dir(extract_dir)
    response = build_verdict_response(feats, display_name, None, None, None)
    response["source"] = "live_ml_prediction"
    return response

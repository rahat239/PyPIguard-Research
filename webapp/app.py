"""
PyPIGuard Web App - Flask Backend
====================================================================
A deployable web interface for pre-install malicious PyPI package detection.

Run locally:
    pip install -r requirements.txt
    python app.py

Deploy to Render (or similar):
    - Build command: pip install -r requirements.txt
    - Start command: gunicorn app:app
"""

import os
import re
import sys
import math
import json
import tarfile
import zipfile
import tempfile
from collections import Counter

import requests
import joblib
import numpy as np
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "pypiguard_model.joblib")
KNOWN_PACKAGES_PATH = os.path.join(os.path.dirname(__file__), "known_packages.json")
_model_bundle = None
_known_packages = None


def get_model():
    global _model_bundle
    if _model_bundle is None:
        _model_bundle = joblib.load(MODEL_PATH)
    return _model_bundle


def get_known_packages():
    global _known_packages
    if _known_packages is None:
        with open(KNOWN_PACKAGES_PATH) as f:
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

    # Derived features (matching Phase 3 feature engineering)
    feats["code_density"] = feats["py_code_length"] / max(feats["num_files"], 1)
    feats["py_file_ratio"] = feats["num_py_files"] / max(feats["num_files"], 1)
    feats["suspicious_indicator_count"] = sum(v for k, v in feats.items() if k.startswith("has_"))
    feats["avg_file_size"] = feats["total_size_bytes"] / max(feats["num_files"], 1)
    feats["is_unusually_small"] = int(feats["py_code_length"] <= 500)  # static approximation of training threshold

    return feats


def fetch_package_metadata(package_name):
    resp = requests.get(f"https://pypi.org/pypi/{package_name}/json", timeout=10)
    if resp.status_code != 200:
        return None, f"Package '{package_name}' was not found on PyPI."
    data = resp.json()
    urls = data.get("urls", [])
    sdist = next((u for u in urls if u["packagetype"] == "sdist"), None)
    if not sdist:
        return None, f"No source distribution available for '{package_name}' (wheel-only package)."
    return {
        "sdist_url": sdist["url"],
        "filename": sdist["filename"],
        "version": data.get("info", {}).get("version"),
        "author": data.get("info", {}).get("author") or "Unknown",
        "summary": data.get("info", {}).get("summary") or "",
        "home_page": data.get("info", {}).get("home_page") or "",
    }, None


# Common package-name -> import-name mismatches (the import name differs from the
# PyPI distribution name), so lookups actually find the right package.
IMPORT_TO_PYPI_NAME = {
    "cv2": "opencv-python",
    "sklearn": "scikit-learn",
    "PIL": "pillow",
    "yaml": "pyyaml",
    "bs4": "beautifulsoup4",
    "dotenv": "python-dotenv",
    "google": "google-api-python-client",
    "Crypto": "pycryptodome",
    "jwt": "pyjwt",
    "OpenSSL": "pyopenssl",
    "serial": "pyserial",
    "docx": "python-docx",
    "pptx": "python-pptx",
    "usb": "pyusb",
}

STDLIB_MODULES = set(sys.stdlib_module_names) | {"__future__"}

IMPORT_PATTERN = re.compile(r'^\s*(?:import|from)\s+([a-zA-Z_][a-zA-Z0-9_]*)', re.MULTILINE)
PIP_INSTALL_PATTERN = re.compile(
    r'^\s*[!%]?\s*pip3?\s+install\s+(?:-\S+\s+)*([^\n#]+)', re.MULTILINE
)


def extract_packages_from_notebook(notebook_json):
    """Extract every third-party package name referenced in a Jupyter notebook,
    via both `import` statements and `pip install` shell/magic commands in code cells."""
    packages = set()

    cells = notebook_json.get("cells", [])
    for cell in cells:
        if cell.get("cell_type") != "code":
            continue
        source = cell.get("source", "")
        if isinstance(source, list):
            source = "".join(source)

        for match in IMPORT_PATTERN.finditer(source):
            mod = match.group(1)
            if mod not in STDLIB_MODULES:
                packages.add(mod)

        for match in PIP_INSTALL_PATTERN.finditer(source):
            args_str = match.group(1)
            for token in args_str.split():
                token = token.strip()
                if token.startswith("-"):
                    continue
                # strip version pins like package==1.2.3, package>=1.0
                pkg = re.split(r'[<>=!~\[]', token)[0].strip()
                if pkg:
                    packages.add(pkg)

    # Normalize known import-name -> pypi-name mismatches
    normalized = set()
    for pkg in packages:
        normalized.add(IMPORT_TO_PYPI_NAME.get(pkg, pkg))

    return sorted(normalized)


@app.route("/scan-notebook", methods=["POST"])
def scan_notebook():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400
    uploaded = request.files["file"]
    if uploaded.filename == "":
        return jsonify({"error": "No file selected."}), 400
    if not uploaded.filename.endswith(".ipynb"):
        return jsonify({"error": "Please upload a .ipynb (Jupyter notebook) file."}), 400

    MAX_SIZE = 10 * 1024 * 1024
    uploaded.seek(0, os.SEEK_END)
    size = uploaded.tell()
    uploaded.seek(0)
    if size > MAX_SIZE:
        return jsonify({"error": "Notebook too large (10 MB limit)."}), 400

    try:
        notebook_json = json.load(uploaded.stream)
    except Exception:
        return jsonify({"error": "Could not parse this file as a valid .ipynb notebook."}), 400

    packages = extract_packages_from_notebook(notebook_json)
    if not packages:
        return jsonify({
            "notebook_name": uploaded.filename,
            "total_packages": 0,
            "flagged_count": 0,
            "results": [],
            "message": "No third-party package imports or pip installs were found in this notebook.",
        })

    known = get_known_packages()
    MAX_LIVE_CHECKS = 12  # cap live PyPI lookups to keep response time reasonable
    live_checks_used = 0
    results = []

    for pkg in packages:
        key = pkg.strip().lower()
        known_entry = known.get(key)
        if known_entry:
            results.append({
                "package_name": pkg,
                "verdict": known_entry["label"],
                "confidence": 100.0,
                "source": "verified_dataset",
            })
            continue

        if live_checks_used >= MAX_LIVE_CHECKS:
            results.append({
                "package_name": pkg,
                "verdict": "unchecked",
                "confidence": None,
                "source": "skipped_limit",
            })
            continue

        live_checks_used += 1
        meta, error = fetch_package_metadata(pkg)
        if error:
            results.append({
                "package_name": pkg,
                "verdict": "unknown",
                "confidence": None,
                "source": "not_found_on_pypi",
            })
            continue

        try:
            with tempfile.TemporaryDirectory() as workdir:
                file_resp = requests.get(meta["sdist_url"], timeout=20)
                archive_path = os.path.join(workdir, meta["filename"])
                with open(archive_path, "wb") as f:
                    f.write(file_resp.content)
                extract_dir = os.path.join(workdir, "extracted")
                os.makedirs(extract_dir, exist_ok=True)
                if archive_path.endswith((".tar.gz", ".tgz")):
                    with tarfile.open(archive_path, "r:gz") as tar:
                        safe_extract_tar(tar, extract_dir)
                elif archive_path.endswith(".zip"):
                    with zipfile.ZipFile(archive_path, "r") as z:
                        safe_extract_zip(z, extract_dir)
                else:
                    raise ValueError("unsupported archive")
                feats = extract_features_from_dir(extract_dir)

            model_bundle = get_model()
            model = model_bundle["model"]
            feature_cols = model_bundle["feature_cols"]
            X = np.array([[feats.get(c, 0) for c in feature_cols]])
            prediction = model.predict(X)[0]
            proba = model.predict_proba(X)[0]
            verdict = "malicious" if prediction == 1 else "benign"
            confidence = float(proba[1] if prediction == 1 else proba[0])
            results.append({
                "package_name": pkg,
                "verdict": verdict,
                "confidence": round(confidence * 100, 1),
                "source": "live_ml_prediction",
            })
        except Exception:
            results.append({
                "package_name": pkg,
                "verdict": "unchecked",
                "confidence": None,
                "source": "analysis_failed",
            })

    flagged_count = sum(1 for r in results if r["verdict"] == "malicious")

    return jsonify({
        "notebook_name": uploaded.filename,
        "total_packages": len(results),
        "flagged_count": flagged_count,
        "results": sorted(results, key=lambda r: (r["verdict"] != "malicious", r["package_name"])),
    })


@app.route("/scan", methods=["POST"])
def scan():
    package_name = (request.json or {}).get("package_name", "").strip()
    if not package_name:
        return jsonify({"error": "Enter a package name to inspect."}), 400
    # Basic sanitization: PyPI package names only contain letters, numbers, ., -, _
    if not re.match(r'^[A-Za-z0-9._-]+$', package_name):
        return jsonify({"error": "Invalid package name format."}), 400

    # STEP 1: check against our verified research dataset first. If this exact
    # package name was one of the 5,900 real packages used to build and validate
    # this project (many of them real historical malware no longer present on
    # the live registry), return the actual ground-truth label instantly --
    # this is a verified fact from the dataset, not a live model guess.
    known = get_known_packages()
    known_entry = known.get(package_name.strip().lower())
    if known_entry:
        return jsonify({
            "package_name": package_name,
            "version": None,
            "author": None,
            "summary": None,
            "verdict": known_entry["label"],
            "confidence": 100.0,
            "flagged_indicators": [],
            "stats": None,
            "source": "verified_dataset",
            "dataset_origin": known_entry["source"],
        })

    # STEP 2: not in our verified dataset -- fall back to a live scan against
    # the current PyPI registry using the trained ML model.
    meta, error = fetch_package_metadata(package_name)
    if error:
        return jsonify({"error": error}), 404

    try:
        with tempfile.TemporaryDirectory() as workdir:
            file_resp = requests.get(meta["sdist_url"], timeout=30)
            archive_path = os.path.join(workdir, meta["filename"])
            with open(archive_path, "wb") as f:
                f.write(file_resp.content)

            extract_dir = os.path.join(workdir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)
            if archive_path.endswith((".tar.gz", ".tgz")):
                with tarfile.open(archive_path, "r:gz") as tar:
                    safe_extract_tar(tar, extract_dir)
            elif archive_path.endswith(".zip"):
                with zipfile.ZipFile(archive_path, "r") as z:
                    safe_extract_zip(z, extract_dir)
            else:
                return jsonify({"error": "Unsupported archive format."}), 400

            feats = extract_features_from_dir(extract_dir)
    except Exception as e:
        return jsonify({"error": f"Could not analyze package contents: {str(e)}"}), 500

    response = build_verdict_response(feats, package_name, meta["version"], meta["author"], meta["summary"])
    response["source"] = "live_ml_prediction"
    return jsonify(response)


@app.route("/scan-file", methods=["POST"])
def scan_file():
    """Analyze a locally uploaded .tar.gz/.zip archive -- for demoing detection on
    real archived malicious samples that no longer exist on the live registry
    (PyPI removes malicious packages once discovered, so live lookups mostly
    return benign verdicts -- this endpoint lets you test the FLAGGED path
    directly against real historical malware)."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400
    uploaded = request.files["file"]
    if uploaded.filename == "":
        return jsonify({"error": "No file selected."}), 400
    if not uploaded.filename.endswith((".tar.gz", ".tgz", ".zip", ".whl")):
        return jsonify({"error": "Unsupported file type. Upload a .tar.gz, .tgz, .zip, or .whl file."}), 400

    MAX_SIZE = 20 * 1024 * 1024  # 20 MB cap
    uploaded.seek(0, os.SEEK_END)
    size = uploaded.tell()
    uploaded.seek(0)
    if size > MAX_SIZE:
        return jsonify({"error": "File too large (20 MB limit)."}), 400

    try:
        with tempfile.TemporaryDirectory() as workdir:
            archive_path = os.path.join(workdir, uploaded.filename)
            uploaded.save(archive_path)

            extract_dir = os.path.join(workdir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)
            if archive_path.endswith((".tar.gz", ".tgz")):
                with tarfile.open(archive_path, "r:gz") as tar:
                    safe_extract_tar(tar, extract_dir)
            elif archive_path.endswith((".zip", ".whl")):
                with zipfile.ZipFile(archive_path, "r") as z:
                    safe_extract_zip(z, extract_dir)

            feats = extract_features_from_dir(extract_dir)
    except Exception as e:
        return jsonify({"error": f"Could not analyze uploaded file: {str(e)}"}), 500

    display_name = uploaded.filename.rsplit(".tar.gz", 1)[0].rsplit(".zip", 1)[0].rsplit(".tgz", 1)[0]
    response = build_verdict_response(feats, display_name, None, "Uploaded file", "Locally uploaded package archive")
    response["source"] = "live_ml_prediction"
    return jsonify(response)


def build_verdict_response(feats, package_name, version, author, summary):
    model_bundle = get_model()
    model = model_bundle["model"]
    feature_cols = model_bundle["feature_cols"]

    X = np.array([[feats.get(c, 0) for c in feature_cols]])
    prediction = model.predict(X)[0]
    proba = model.predict_proba(X)[0]
    verdict = "malicious" if prediction == 1 else "benign"
    confidence = float(proba[1] if prediction == 1 else proba[0])

    flagged_indicators = [
        {"key": k, "label": FEATURE_LABELS.get(k, k)}
        for k in feats if k.startswith("has_") and feats[k] == 1 and k in SUSPICIOUS_PATTERNS
    ]

    return {
        "package_name": package_name,
        "version": version,
        "author": author,
        "summary": summary,
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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)

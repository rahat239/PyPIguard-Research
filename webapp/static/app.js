const input = document.getElementById("package-input");
const btn = document.getElementById("inspect-btn");
const resultSection = document.getElementById("result-section");
const errorBox = document.getElementById("error-box");
const loadingBox = document.getElementById("loading-box");
const chips = document.querySelectorAll(".chip");

async function inspect(packageName) {
  if (!packageName) return;

  errorBox.classList.add("hidden");
  resultSection.classList.add("hidden");
  loadingBox.classList.remove("hidden");
  btn.disabled = true;

  try {
    const res = await fetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package_name: packageName }),
    });
    const data = await res.json();

    loadingBox.classList.add("hidden");
    btn.disabled = false;

    if (!res.ok) {
      errorBox.textContent = data.error || "Something went wrong during inspection.";
      errorBox.classList.remove("hidden");
      return;
    }

    renderResult(data);
  } catch (err) {
    loadingBox.classList.add("hidden");
    btn.disabled = false;
    errorBox.textContent = "Could not reach the inspection service. Please try again. (Very large packages may exceed the hosting timeout -- try a local file upload instead.)";
    errorBox.classList.remove("hidden");
  }
}

function renderResult(data) {
  document.getElementById("result-name").textContent = data.package_name;
  document.getElementById("result-version").textContent = data.version ? `v${data.version}` : "";
  document.getElementById("result-summary").textContent = data.summary || "";
  document.getElementById("result-author").textContent = data.author ? `Author: ${data.author}` : "";

  const stamp = document.getElementById("stamp");
  const stampText = document.getElementById("stamp-text");
  const isMalicious = data.verdict === "malicious";
  const isOOD = data.out_of_distribution === true;

  stamp.classList.remove("verdict-benign", "verdict-malicious", "stamp-appear");
  void stamp.offsetWidth; // restart animation

  if (isOOD) {
    // This package is far larger than anything in the training data --
    // the model's verdict here is not reliable, so we show a distinct
    // warning state instead of a potentially wrong CLEARED/FLAGGED stamp.
    stamp.classList.add("verdict-unreliable", "stamp-appear");
    stampText.textContent = "UNRELIABLE";
  } else {
    stamp.classList.add(isMalicious ? "verdict-malicious" : "verdict-benign", "stamp-appear");
    stampText.textContent = isMalicious ? "FLAGGED" : "CLEARED";
  }

  document.getElementById("confidence-value").textContent = `${data.confidence}%`;
  const fill = document.getElementById("confidence-bar-fill");
  fill.classList.remove("verdict-benign", "verdict-malicious");
  fill.classList.add(isMalicious ? "verdict-malicious" : "verdict-benign");
  requestAnimationFrame(() => { fill.style.width = `${data.confidence}%`; });

  const sourceBadge = document.getElementById("source-badge");
  if (data.source === "verified_dataset") {
    sourceBadge.textContent = `VERIFIED DATASET RECORD (${data.dataset_origin})`;
    sourceBadge.className = "source-badge source-verified";
  } else {
    sourceBadge.textContent = "LIVE ML PREDICTION";
    sourceBadge.className = "source-badge source-live";
  }

  const list = document.getElementById("findings-list");
  list.innerHTML = "";

  if (isOOD) {
    const warningLi = document.createElement("li");
    warningLi.style.cssText = "border-left-color: var(--stamp-amber); background: rgba(184,134,46,0.12); font-weight: 600;";
    warningLi.textContent = `This package (${data.stats ? data.stats.num_files : "?"} files) is far larger than any package in our training data. The model's verdict for packages this size is not reliable -- treat this result as informational only, not a determination.`;
    list.appendChild(warningLi);
  }

  if (!data.flagged_indicators || data.flagged_indicators.length === 0) {
    const li = document.createElement("li");
    li.className = "findings-empty";
    li.textContent = data.source === "verified_dataset"
      ? "Verified from dataset record -- no live code analysis performed for this entry."
      : "No suspicious code patterns declared.";
    list.appendChild(li);
  } else {
    data.flagged_indicators.forEach((ind) => {
      const li = document.createElement("li");
      li.textContent = ind.label;
      list.appendChild(li);
    });
  }

  const statsStrip = document.querySelector(".stats-strip");
  if (data.stats) {
    statsStrip.classList.remove("hidden");
    document.getElementById("stat-files").textContent = data.stats.num_files;
    document.getElementById("stat-pyfiles").textContent = data.stats.num_py_files;
    document.getElementById("stat-length").textContent = data.stats.code_length.toLocaleString();
    document.getElementById("stat-entropy").textContent = data.stats.entropy;
  } else {
    statsStrip.classList.add("hidden");
  }

  document.getElementById("ticket-timestamp").textContent = new Date().toLocaleString();

  resultSection.classList.remove("hidden");
  resultSection.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

btn.addEventListener("click", () => inspect(input.value.trim()));
input.addEventListener("keydown", (e) => {
  if (e.key === "Enter") inspect(input.value.trim());
});
chips.forEach((chip) => {
  chip.addEventListener("click", () => {
    input.value = chip.dataset.pkg;
    inspect(chip.dataset.pkg);
  });
});

const fileInput = document.getElementById("file-input");
const uploadBtn = document.getElementById("upload-btn");

async function inspectFile(file) {
  if (!file) return;

  errorBox.classList.add("hidden");
  resultSection.classList.add("hidden");
  loadingBox.classList.remove("hidden");
  uploadBtn.disabled = true;

  const formData = new FormData();
  formData.append("file", file);

  try {
    const res = await fetch("/scan-file", { method: "POST", body: formData });
    const data = await res.json();

    loadingBox.classList.add("hidden");
    uploadBtn.disabled = false;

    if (!res.ok) {
      errorBox.textContent = data.error || "Something went wrong during inspection.";
      errorBox.classList.remove("hidden");
      return;
    }

    renderResult(data);
  } catch (err) {
    loadingBox.classList.add("hidden");
    uploadBtn.disabled = false;
    errorBox.textContent = "Could not reach the inspection service. Please try again. (Very large packages may exceed the hosting timeout -- try a local file upload instead.)";
    errorBox.classList.remove("hidden");
  }
}

uploadBtn.addEventListener("click", () => {
  if (fileInput.files.length > 0) {
    inspectFile(fileInput.files[0]);
  } else {
    errorBox.textContent = "Choose a file first.";
    errorBox.classList.remove("hidden");
  }
});

const notebookInput = document.getElementById("notebook-input");
const notebookBtn = document.getElementById("notebook-btn");
const notebookResultSection = document.getElementById("notebook-result-section");

async function scanNotebook(file) {
  if (!file) return;

  errorBox.classList.add("hidden");
  notebookResultSection.classList.add("hidden");
  loadingBox.classList.remove("hidden");
  notebookBtn.disabled = true;

  const formData = new FormData();
  formData.append("file", file);

  try {
    const res = await fetch("/scan-notebook", { method: "POST", body: formData });
    const data = await res.json();

    loadingBox.classList.add("hidden");
    notebookBtn.disabled = false;

    if (!res.ok) {
      errorBox.textContent = data.error || "Could not scan this notebook.";
      errorBox.classList.remove("hidden");
      return;
    }

    renderNotebookResult(data);
  } catch (err) {
    loadingBox.classList.add("hidden");
    notebookBtn.disabled = false;
    errorBox.textContent = "Could not reach the inspection service. Please try again. (Very large packages may exceed the hosting timeout -- try a local file upload instead.)";
    errorBox.classList.remove("hidden");
  }
}

function renderNotebookResult(data) {
  const summary = document.getElementById("notebook-summary");
  if (data.total_packages === 0) {
    summary.textContent = data.message || "No third-party packages found in this notebook.";
  } else {
    summary.innerHTML = `<strong>${data.notebook_name}</strong>: ${data.total_packages} package(s) referenced, ` +
      `<span style="color: var(--stamp-red); font-weight:600;">${data.flagged_count} flagged as malicious</span>.`;
  }

  const list = document.getElementById("notebook-findings-list");
  list.innerHTML = "";

  if (data.results.length === 0) {
    const li = document.createElement("li");
    li.className = "findings-empty";
    li.textContent = "Nothing to report.";
    list.appendChild(li);
  } else {
    data.results.forEach((r) => {
      const li = document.createElement("li");
      let verdictLabel, style;
      if (r.verdict === "malicious") {
        verdictLabel = `FLAGGED (${r.source === "verified_dataset" ? "verified" : r.confidence + "%"})`;
        style = "border-left-color: var(--stamp-red); background: rgba(166,51,42,0.08);";
      } else if (r.verdict === "benign") {
        verdictLabel = `cleared (${r.source === "verified_dataset" ? "verified" : r.confidence + "%"})`;
        style = "border-left-color: var(--stamp-green); background: rgba(46,94,69,0.06);";
      } else if (r.verdict === "not_found_on_pypi" || r.verdict === "unknown") {
        verdictLabel = "not found on PyPI";
        style = "border-left-color: var(--line-strong); color: var(--ink-soft);";
      } else {
        verdictLabel = "not checked (limit reached)";
        style = "border-left-color: var(--line-strong); color: var(--ink-soft);";
      }
      li.setAttribute("style", style);
      li.textContent = `${r.package_name} \u2014 ${verdictLabel}`;
      list.appendChild(li);
    });
  }

  document.getElementById("notebook-timestamp").textContent = new Date().toLocaleString();
  notebookResultSection.classList.remove("hidden");
  notebookResultSection.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

notebookBtn.addEventListener("click", () => {
  if (notebookInput.files.length > 0) {
    scanNotebook(notebookInput.files[0]);
  } else {
    errorBox.textContent = "Choose a notebook file first.";
    errorBox.classList.remove("hidden");
  }
});

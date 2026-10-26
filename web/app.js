/* SOC 2 Evidence Kit demo page.
 *
 * Renders a soc2kit report.json: the bundled sample, or a file the visitor opens.
 * Security notes:
 *  - The page makes no network requests (CSP connect-src 'none'); a visitor's file is read with FileReader only.
 *  - Report content is untrusted. It is validated, length-capped, and only ever written with textContent.
 */
(function () {
  "use strict";

  var MAX_BYTES = 15 * 1024 * 1024;
  var STATUSES = ["PASS", "FAIL", "ERROR", "N/A"];
  var STATUS_LABEL = { PASS: "Passes", FAIL: "Fails", ERROR: "Couldn't run", "N/A": "N/A" };
  var SEVERITY_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  var current = null;      // the report currently shown
  var filter = "FAIL";
  var animation = null;

  // ------------------------------------------------------------ helpers
  function $(id) { return document.getElementById(id); }

  function el(tag, props, children) {
    var node = document.createElement(tag);
    if (props) {
      Object.keys(props).forEach(function (k) {
        if (k === "text") node.textContent = props[k];
        else if (k === "className") node.className = props[k];
        else node.setAttribute(k, props[k]);
      });
    }
    (children || []).forEach(function (c) { if (c) node.appendChild(c); });
    return node;
  }

  function str(v, max) {
    if (v === null || v === undefined) return "";
    var s = String(v);
    return s.length > max ? s.slice(0, max) + "…" : s;
  }

  function list(v, max) { return Array.isArray(v) ? v.slice(0, max) : []; }

  function plural(n, word) { return n + " " + word + (n === 1 ? "" : "s"); }

  function formatDate(iso) {
    var d = new Date(iso);
    if (isNaN(d.getTime())) return str(iso, 40);
    return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  // ----------------------------------------------------------- validate
  function normalise(raw) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("This file isn't a soc2kit report.");
    if (!raw.tool || raw.tool.name !== "soc2kit") throw new Error("This JSON wasn't produced by soc2kit. Open soc2-evidence/report.json.");
    if (!Array.isArray(raw.results)) throw new Error("The report has no results list.");
    if (raw.results.length > 10000) throw new Error("The report is larger than this page supports.");

    var results = raw.results.map(function (r) {
      var status = STATUSES.indexOf(r && r.status) >= 0 ? r.status : "ERROR";
      return {
        check_id: str(r.check_id, 20),
        title: str(r.title, 200),
        criteria: list(r.criteria, 10).map(function (c) { return str(c, 10); }),
        severity: SEVERITY_RANK.hasOwnProperty(r.severity) ? r.severity : "LOW",
        region: str(r.region, 30),
        status: status,
        summary: str(r.summary, 300),
        remediation: str(r.remediation, 600),
        error: r.error ? str(r.error, 600) : "",
        evidence_file: str(r.evidence_file, 120),
        findings: list(r.findings, 500).map(function (f) {
          return { resource: str(f && f.resource, 300), status: str(f && f.status, 10), detail: str(f && f.detail, 300) };
        })
      };
    });

    var counts = { PASS: 0, FAIL: 0, ERROR: 0, "N/A": 0 };
    results.forEach(function (r) { counts[r.status] += 1; });
    var evaluated = counts.PASS + counts.FAIL;

    var criteria = list(raw.criteria, 200).map(function (c) {
      return {
        criterion: str(c.criterion, 10),
        name: str(c.name, 120),
        automated_checks: list(c.automated_checks, 100).map(function (x) { return str(x, 20); }),
        manual_controls: list(c.manual_controls, 100).map(function (x) { return str(x, 20); })
      };
    });

    return {
      account_id: str(raw.account_id, 20),
      principal_arn: str(raw.principal_arn, 200),
      regions: list(raw.regions, 40).map(function (x) { return str(x, 30); }),
      finished_at: str(raw.finished_at, 40),
      // Recomputed from the results rather than trusted from the file.
      counts: counts,
      score: evaluated ? Math.round((100 * counts.PASS) / evaluated) : 0,
      results: results,
      criteria: criteria,
      manual_count: list(raw.manual_controls, 500).length,
      sample: raw.sample ? { company: str(raw.sample.company, 80) } : null
    };
  }

  // -------------------------------------------------------------- board
  function resultsFor(report, criterion) {
    return report.results
      .filter(function (r) { return r.criteria.indexOf(criterion) >= 0; })
      .sort(function (a, b) { return (a.check_id + a.region).localeCompare(b.check_id + b.region); });
  }

  function buildBoard(report) {
    var board = $("board");
    board.textContent = "";
    var pips = [];
    var manualOnly = 0;
    report.criteria.forEach(function (c) {
      var rs = resultsFor(report, c.criterion);
      var right;
      if (!rs.length) { manualOnly += 1; return; }  // procedural-only criteria live in the coverage table
      if (rs.length) {
        right = el("span", { className: "pips", "aria-hidden": "true" });
        rs.forEach(function (r) {
          var p = el("i", { className: "pip", "data-s": r.status });
          right.appendChild(p);
          pips.push({ pip: p, key: r.check_id + "|" + r.region });
        });
      } else {
        right = el("span", { className: "manual-only", text: plural(c.manual_controls.length, "manual control") });
      }
      board.appendChild(el("li", { className: "crit" }, [
        el("span", { className: "crit-id", text: c.criterion }),
        el("span", { className: "crit-name", text: c.name, title: c.name }),
        right
      ]));
    });
    if (manualOnly) board.appendChild(el("li", { className: "crit-more", text: "+ " + manualOnly + (manualOnly === 1 ? " more criterion" : " more criteria") + " covered by manual controls in the workbook" }));
    $("board-account").textContent = report.sample ? "northwind-health" : "account " + report.account_id;
    return pips;
  }

  function animateBoard(report, done) {
    if (animation) clearInterval(animation);
    var pips = buildBoard(report);
    // Light every square belonging to the same check result together, in check order.
    var keys = [];
    pips.forEach(function (p) { if (keys.indexOf(p.key) < 0) keys.push(p.key); });
    keys.sort();
    var progress = $("board-progress");
    if (reduceMotion) {
      pips.forEach(function (p) { p.pip.classList.add("on"); });
      progress.textContent = plural(keys.length, "result");
      done();
      return;
    }
    var i = 0;
    animation = setInterval(function () {
      var key = keys[i];
      pips.forEach(function (p) { if (p.key === key) p.pip.classList.add("on"); });
      i += 1;
      progress.textContent = "Checking " + i + " of " + keys.length;
      if (i >= keys.length) {
        clearInterval(animation);
        animation = null;
        progress.textContent = report.counts.FAIL + " failing · " + report.counts.PASS + " passing";
        done();
      }
    }, 28);
  }

  // ------------------------------------------------------------- report
  function renderStats(report) {
    var stats = $("stats");
    stats.textContent = "";
    [["score", "Automated score", report.score + "%"],
     ["FAIL", "Failing", report.counts.FAIL],
     ["PASS", "Passing", report.counts.PASS],
     ["ERROR", "Couldn't evaluate", report.counts.ERROR],
     ["N/A", "Not applicable", report.counts["N/A"]]].forEach(function (s) {
      stats.appendChild(el("div", { className: "stat", "data-k": s[0] }, [
        el("dt", { text: s[1] }), el("dd", { text: String(s[2]) })
      ]));
    });
  }

  function sortResults(a, b) {
    var order = { FAIL: 0, ERROR: 1, PASS: 2, "N/A": 3 };
    return (order[a.status] - order[b.status]) ||
      (SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]) ||
      a.check_id.localeCompare(b.check_id) || a.region.localeCompare(b.region);
  }

  function resultItem(r) {
    var meta = el("p", { className: "result-meta" });
    [r.check_id, r.severity.charAt(0) + r.severity.slice(1).toLowerCase(), r.criteria.join(", "), r.region].forEach(function (part, i) {
      if (i) meta.appendChild(el("span", { className: "sep", text: "·", "aria-hidden": "true" }));
      meta.appendChild(document.createTextNode(part));
    });

    var body = el("div", { className: "result-body" }, [
      el("h3", { text: r.title }), meta, el("p", { className: "result-summary", text: r.summary })
    ]);

    if (r.status === "FAIL" || r.status === "ERROR") {
      var inner = el("div", { className: "more-body" });
      var failing = r.findings.filter(function (f) { return f.status === "FAIL"; });
      if (failing.length) {
        var ul = el("ul", { className: "res-list" });
        failing.slice(0, 50).forEach(function (f) {
          ul.appendChild(el("li", null, [el("code", { text: f.resource }), document.createTextNode(" — " + f.detail)]));
        });
        if (failing.length > 50) ul.appendChild(el("li", { text: "and " + (failing.length - 50) + " more in the workbook" }));
        inner.appendChild(el("div", null, [el("h4", { text: "Resources" }), ul]));
      }
      if (r.error) inner.appendChild(el("div", null, [el("h4", { text: "Why it couldn't run" }), el("p", { text: r.error })]));
      inner.appendChild(el("div", null, [el("h4", { text: "How to fix" }), el("p", { text: r.remediation })]));
      if (r.evidence_file) inner.appendChild(el("div", null, [el("h4", { text: "Evidence" }), el("p", null, [el("code", { text: r.evidence_file })])]));
      body.appendChild(el("details", { className: "more" }, [el("summary", { text: r.status === "FAIL" ? "Resources and fix" : "Details" }), inner]));
    }

    return el("li", { className: "result", "data-s": r.status }, [
      el("span", { className: "tag", text: STATUS_LABEL[r.status] }), body
    ]);
  }

  function renderResults() {
    var ul = $("results");
    ul.textContent = "";
    var shown = current.results.filter(function (r) {
      return filter === "ALL" || r.status === filter;
    }).sort(sortResults);
    if (!shown.length) {
      ul.appendChild(el("li", { className: "empty", text: "Nothing in this view." }));
      return;
    }
    shown.forEach(function (r) { ul.appendChild(resultItem(r)); });
  }

  function renderFilters() {
    document.querySelectorAll(".chip").forEach(function (chip) {
      var k = chip.getAttribute("data-filter");
      var n = k === "ALL" ? current.results.length : current.counts[k];
      var label = chip.firstChild.nodeType === 3 ? chip.firstChild.nodeValue : chip.textContent;
      chip.textContent = label;
      chip.appendChild(el("span", { className: "n", text: String(n) }));
      chip.setAttribute("aria-pressed", String(k === filter));
    });
  }

  function renderCriteria(report) {
    var body = $("criteria-body");
    body.textContent = "";
    report.criteria.forEach(function (c) {
      var rs = resultsFor(report, c.criterion);
      var f = rs.filter(function (r) { return r.status === "FAIL"; }).length;
      var p = rs.filter(function (r) { return r.status === "PASS"; }).length;
      var auto = rs.length
        ? el("td", { className: "counts" }, [
            el("b", { className: "f", text: f + " failing" }), document.createTextNode(" · "),
            el("b", { className: "p", text: p + " passing" })])
        : el("td", { text: "—" });
      body.appendChild(el("tr", null, [
        el("th", { scope: "row", text: c.criterion }), el("td", { text: c.name }), auto,
        el("td", { text: c.manual_controls.join(", ") || "—" })
      ]));
    });
  }

  function render(report, sourceLabel) {
    current = report;
    filter = report.counts.FAIL ? "FAIL" : "ALL";
    $("report-source").textContent = sourceLabel;
    $("report-meta").textContent = "AWS account " + report.account_id + " · scanned " + formatDate(report.finished_at) +
      " · " + plural(report.regions.length, "region") + " · " + plural(report.results.length, "check result");
    $("downloads").hidden = !report.sample;
    $("report-note").textContent = "Automated checks cover the technical part of SOC 2. " +
      (report.manual_count ? "The workbook lists " + report.manual_count + " procedural controls that still need evidence. " : "") +
      "Criteria mappings are guidance; your auditor decides what is sufficient.";
    renderStats(report);
    renderFilters();
    renderResults();
    renderCriteria(report);
    $("report").hidden = false;
  }

  // ------------------------------------------------------------- sample
  var sample = null;
  try { sample = window.SOC2KIT_SAMPLE ? normalise(window.SOC2KIT_SAMPLE) : null; } catch (e) { sample = null; }
  if (sample) buildBoard(sample);

  $("run-sample").addEventListener("click", function () {
    if (!sample) return;
    var btn = this;
    btn.disabled = true;
    animateBoard(sample, function () {
      btn.disabled = false;
      btn.textContent = "Replay the sample";
      render(sample, "Sample · " + (sample.sample ? sample.sample.company : "fictional company"));
      $("report").scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "start" });
    });
  });

  document.querySelectorAll(".chip").forEach(function (chip) {
    chip.addEventListener("click", function () {
      filter = chip.getAttribute("data-filter");
      renderFilters();
      renderResults();
    });
  });

  // --------------------------------------------------------- open file
  var status = $("file-status");
  function setStatus(text, tone) { status.textContent = text; status.setAttribute("data-tone", tone || ""); }

  function openFile(file) {
    if (!file) return;
    if (file.size > MAX_BYTES) { setStatus("That file is over 15 MB. Open soc2-evidence/report.json.", "err"); return; }
    var reader = new FileReader();
    reader.onerror = function () { setStatus("The file couldn't be read.", "err"); };
    reader.onload = function () {
      var report;
      try {
        report = normalise(JSON.parse(String(reader.result)));
      } catch (e) {
        setStatus(e instanceof SyntaxError ? "That file isn't valid JSON." : e.message, "err");
        return;
      }
      setStatus("Opened " + str(file.name, 80) + ". It stays in this browser tab.", "ok");
      buildBoard(report).forEach(function (p) { p.pip.classList.add("on"); });
      $("board-progress").textContent = report.counts.FAIL + " failing · " + report.counts.PASS + " passing";
      render(report, "Your report · read locally, not uploaded");
      $("report").scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "start" });
    };
    reader.readAsText(file);
  }

  var drop = $("drop");
  $("file").addEventListener("change", function () { openFile(this.files && this.files[0]); this.value = ""; });
  ["dragenter", "dragover"].forEach(function (t) {
    drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.add("over"); });
  });
  ["dragleave", "drop"].forEach(function (t) {
    drop.addEventListener(t, function () { drop.classList.remove("over"); });
  });
  drop.addEventListener("drop", function (e) {
    e.preventDefault();
    openFile(e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]);
  });
  // Stop a file dropped anywhere else from navigating the tab away.
  window.addEventListener("dragover", function (e) { e.preventDefault(); });
  window.addEventListener("drop", function (e) { e.preventDefault(); });

  // -------------------------------------------------------------- copy
  document.querySelectorAll(".copy").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var text = $(btn.getAttribute("data-copy")).textContent.trim();
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(text).then(function () {
        btn.textContent = "Copied";
        setTimeout(function () { btn.textContent = "Copy"; }, 1600);
      });
    });
  });
})();

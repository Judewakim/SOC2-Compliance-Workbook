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
  var MARK = { PASS: "✓", FAIL: "✗", ERROR: "?", "N/A": "–" };
  var MARK_LABEL = { PASS: "Passed", FAIL: "Failed", ERROR: "Not tested", "N/A": "Nothing to test" };
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

    // One verdict per control: fails if it fails in any region; passes only if nothing failed or went untested.
    var groups = {};
    var orderIds = [];
    results.forEach(function (r) {
      if (!groups[r.check_id]) { groups[r.check_id] = []; orderIds.push(r.check_id); }
      groups[r.check_id].push(r);
    });
    var checks = orderIds.map(function (id) {
      var rows = groups[id];
      var first = rows[0];
      var status = ["FAIL", "ERROR", "PASS"].filter(function (s) {
        return rows.some(function (r) { return r.status === s; });
      })[0] || "N/A";
      var by = { PASS: [], FAIL: [], ERROR: [], "N/A": [] };
      rows.forEach(function (r) { by[r.status].push(r.region); });
      var regional = rows.length > 1 || (first.region && first.region !== "global");
      var applicable = rows.length - by["N/A"].length;
      var summary = first.summary;
      var resourceLevel = rows.some(function (r) { return r.findings.some(function (f) { return f.resource !== r.region; }); });
      var totalRes = 0, badRes = 0;
      rows.forEach(function (r) { r.findings.forEach(function (f) { totalRes += 1; if (f.status === "FAIL") badRes += 1; }); });
      if (regional && rows.length > 1) {
        if (status === "FAIL" && resourceLevel) {
          summary = badRes + " of " + totalRes + " resources fail (" + by.FAIL.slice(0, 4).join(", ") + (by.FAIL.length > 4 ? " and more" : "") + ")";
        } else if (status === "PASS" && resourceLevel) {
          summary = "All " + totalRes + " resources pass";
        } else if (status === "FAIL") {
          summary = "Fails in " + by.FAIL.length + " of " + applicable + " regions: " + by.FAIL.slice(0, 4).join(", ") +
            (by.FAIL.length > 4 ? " and " + (by.FAIL.length - 4) + " more" : "");
        } else if (status === "ERROR") {
          summary = "Couldn't be tested in " + plural(by.ERROR.length, "region");
        } else if (status === "PASS") {
          summary = "Passes in all " + plural(applicable, "region") + " where it applies";
        } else {
          summary = "Nothing to test in any region";
        }
      }
      var findings = [];
      rows.forEach(function (r) {
        r.findings.forEach(function (f) {
          if (f.status === "FAIL") findings.push({ resource: f.resource, detail: f.detail, region: r.region });
        });
      });
      return {
        check_id: first.check_id, title: first.title, criteria: first.criteria, severity: first.severity,
        status: status, summary: summary, remediation: first.remediation,
        region_label: regional && rows.length > 1 ? plural(rows.length, "region") : (first.region || "global"),
        errors: rows.filter(function (r) { return r.error; }).map(function (r) { return r.region + ": " + r.error; }),
        findings: findings,
        evidence_files: rows.filter(function (r) { return r.evidence_file && r.status !== "N/A"; }).map(function (r) { return r.evidence_file; })
      };
    });

    var counts = { PASS: 0, FAIL: 0, ERROR: 0, "N/A": 0 };
    checks.forEach(function (c) { counts[c.status] += 1; });
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
      checks: checks,
      criteria: criteria,
      manual_count: list(raw.manual_controls, 500).length,
      sample: raw.sample ? { company: str(raw.sample.company, 80) } : null
    };
  }

  // -------------------------------------------------------------- sheet
  function resultsFor(report, criterion) {
    return report.checks
      .filter(function (c) { return c.criteria.indexOf(criterion) >= 0; })
      .sort(function (a, b) { return a.check_id.localeCompare(b.check_id); });
  }

  function markClass(status) { return "m-" + (status === "N/A" ? "NA" : status); }

  // Builds one printout line per criterion that has automated results. Returns the rows in print order.
  function buildSheet(report, waiting) {
    var board = $("board");
    board.textContent = "";
    var rows = [];
    var manualOnly = 0;
    report.criteria.forEach(function (c) {
      var rs = resultsFor(report, c.criterion);
      if (!rs.length) { manualOnly += 1; return; }
      var marks = el("span", { className: "marks" });
      rs.forEach(function (r) { marks.appendChild(el("span", { className: markClass(r.status), text: MARK[r.status] })); });
      var passed = rs.filter(function (r) { return r.status === "PASS"; }).length;
      var tested = rs.filter(function (r) { return r.status === "PASS" || r.status === "FAIL"; }).length;
      var row = el("li", { className: "sheet-row" + (waiting ? " waiting" : ""),
                           "aria-label": c.criterion + " " + c.name + ": " + passed + " of " + tested + " passed" }, [
        el("span", { className: "ref", text: c.criterion }),
        el("span", { className: "desc", text: c.name.toUpperCase() }),
        marks,
        el("span", { className: "tally", text: passed + "/" + tested })
      ]);
      board.appendChild(row);
      rows.push(row);
    });
    if (manualOnly) {
      var more = el("li", { className: "sheet-row" + (waiting ? " waiting" : "") }, [
        el("span", { className: "ref", text: "..." }),
        el("span", { className: "desc", text: manualOnly + " MORE CRITERIA ARE PROCEDURAL, SEE WORKBOOK" })
      ]);
      board.appendChild(more);
      rows.push(more);
    }
    var who = report.sample ? (report.sample.company || "SAMPLE").toUpperCase() : "YOUR REPORT";
    $("sheet-title").textContent = "SOC2KIT EVIDENCE RUN   " + who + "   ACCOUNT " + report.account_id;
    return rows;
  }

  function finalLine(report) {
    return "END OF RUN   " + report.counts.FAIL + " FAILED   " + report.counts.PASS + " PASSED   " +
      report.counts.ERROR + " NOT TESTED   SCORE " + report.score + "%";
  }

  function printSheet(report, done) {
    if (animation) clearInterval(animation);
    var rows = buildSheet(report, !reduceMotion);
    var progress = $("board-progress");
    if (reduceMotion) { progress.textContent = finalLine(report); done(); return; }
    var i = 0;
    progress.textContent = "PRINTING...";
    animation = setInterval(function () {
      rows[i].classList.remove("waiting");
      rows[i].classList.add("printed");
      i += 1;
      if (i >= rows.length) {
        clearInterval(animation);
        animation = null;
        progress.textContent = finalLine(report);
        setTimeout(done, 350);
      }
    }, 140);
  }

  // ------------------------------------------------------------- report
  function renderVerdict(report) {
    var v = $("verdict");
    v.textContent = "";
    function n(k, text) { v.appendChild(el("span", { className: "n-" + k, text: text })); }
    n("FAIL", plural(report.counts.FAIL, "control") + " failed");
    v.appendChild(document.createTextNode(", "));
    n("PASS", report.counts.PASS + " passed");
    if (report.counts.ERROR) {
      v.appendChild(document.createTextNode(" and "));
      n("ERROR", report.counts.ERROR + " couldn't be tested");
    }
    v.appendChild(document.createTextNode(". That's " + report.score + "% of the controls the scanner could test."));
  }

  function sortResults(a, b) {
    var order = { FAIL: 0, ERROR: 1, PASS: 2, "N/A": 3 };
    return (order[a.status] - order[b.status]) ||
      (SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]) ||
      a.check_id.localeCompare(b.check_id);
  }

  function resultItem(r) {
    var sev = r.severity.charAt(0) + r.severity.slice(1).toLowerCase();
    var ref = el("p", { className: "result-ref" }, [
      el("b", { text: r.check_id }),
      document.createTextNode("  " + sev + " severity, " + r.criteria.join(" and ") + ", " + r.region_label)
    ]);
    var body = el("div", { className: "result-body" }, [
      el("h3", { text: r.title }), ref, el("p", { className: "result-summary", text: r.summary })
    ]);

    if (r.status === "FAIL" || r.status === "ERROR") {
      var inner = el("div", { className: "more-body" });
      var failing = r.findings;
      if (failing.length) {
        var ul = el("ul", { className: "res-list" });
        failing.slice(0, 50).forEach(function (f) {
          var where = f.region && f.region !== "global" ? " (" + f.region + ")" : "";
          ul.appendChild(el("li", null, [el("code", { text: f.resource }), document.createTextNode(where + ": " + f.detail)]));
        });
        if (failing.length > 50) ul.appendChild(el("li", { text: (failing.length - 50) + " more are listed in the workbook." }));
        inner.appendChild(el("div", null, [el("h4", { text: "Affected resources" }), ul]));
      }
      if (r.errors.length) inner.appendChild(el("div", null, [el("h4", { text: "Why it wasn't tested" }), el("p", { text: r.errors.slice(0, 5).join(" ") })]));
      inner.appendChild(el("div", null, [el("h4", { text: "How to fix it" }), el("p", { text: r.remediation })]));
      if (r.evidence_files.length) {
        var ev = el("p");
        r.evidence_files.slice(0, 6).forEach(function (f, i) { if (i) ev.appendChild(document.createTextNode(" ")); ev.appendChild(el("code", { text: f })); });
        if (r.evidence_files.length > 6) ev.appendChild(document.createTextNode(" and " + (r.evidence_files.length - 6) + " more"));
        inner.appendChild(el("div", null, [el("h4", { text: r.evidence_files.length > 1 ? "Evidence files" : "Evidence file" }), ev]));
      }
      body.appendChild(el("details", { className: "more" }, [el("summary", { text: r.status === "FAIL" ? "Show resources and fix" : "Show details" }), inner]));
    }

    return el("li", { className: "result", "data-s": r.status }, [
      el("span", { className: "mark " + markClass(r.status), title: MARK_LABEL[r.status], "aria-label": MARK_LABEL[r.status], text: MARK[r.status] }),
      body
    ]);
  }

  function renderResults() {
    var ul = $("results");
    ul.textContent = "";
    var shown = current.checks.filter(function (r) { return filter === "ALL" || r.status === filter; }).sort(sortResults);
    if (!shown.length) { ul.appendChild(el("li", { className: "empty", text: "No results in this tab." })); return; }
    shown.forEach(function (r) { ul.appendChild(resultItem(r)); });
  }

  var TAB_LABEL = { FAIL: "Failed", ERROR: "Not tested", PASS: "Passed", ALL: "All" };
  function renderTabs() {
    document.querySelectorAll(".tab").forEach(function (tab) {
      var k = tab.getAttribute("data-filter");
      tab.textContent = TAB_LABEL[k];
      tab.appendChild(el("span", { className: "n", text: String(k === "ALL" ? current.checks.length : current.counts[k]) }));
      tab.setAttribute("aria-pressed", String(k === filter));
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
        ? el("td", { className: "counts" }, [el("span", { className: "f", text: f + " failed" }),
            document.createTextNode(", "), el("span", { className: "p", text: p + " passed" })])
        : el("td", { text: "None, procedural only" });
      body.appendChild(el("tr", null, [
        el("th", { scope: "row", text: c.criterion }), el("td", { text: c.name }), auto,
        el("td", { text: c.manual_controls.join(", ") || "None" })
      ]));
    });
  }

  function render(report, sourceLabel) {
    current = report;
    filter = report.counts.FAIL ? "FAIL" : "ALL";
    $("report-source").textContent = sourceLabel;
    renderVerdict(report);
    $("report-meta").textContent = "AWS account " + report.account_id + ", scanned " + formatDate(report.finished_at) +
      " across " + plural(report.regions.length, "region") + " (" + plural(report.results.length, "region-level result") + ").";
    $("downloads").hidden = !report.sample;
    $("report-note").textContent = "The scanner covers the technical part of SOC 2. " +
      (report.manual_count ? "The workbook lists " + report.manual_count + " procedural controls that still need evidence. " : "") +
      "Criteria mappings are guidance; your auditor decides what's sufficient.";
    renderTabs();
    renderResults();
    renderCriteria(report);
    $("report").hidden = false;
  }

  // ------------------------------------------------------------- sample
  var sample = null;
  try { sample = window.SOC2KIT_SAMPLE ? normalise(window.SOC2KIT_SAMPLE) : null; } catch (e) { sample = null; }
  if (sample) { buildSheet(sample, false); $("board-progress").textContent = finalLine(sample); }

  $("run-sample").addEventListener("click", function () {
    if (!sample) return;
    var btn = this;
    btn.disabled = true;
    printSheet(sample, function () {
      btn.disabled = false;
      btn.textContent = "Print it again";
      render(sample, "Sample scan of " + (sample.sample ? sample.sample.company : "a fictional company") + ".");
      $("report").scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "start" });
    });
  });

  document.querySelectorAll(".tab").forEach(function (tab) {
    tab.addEventListener("click", function () {
      filter = tab.getAttribute("data-filter");
      renderTabs();
      renderResults();
    });
  });

  // --------------------------------------------------------- open file
  var status = $("file-status");
  function setStatus(text, tone) { status.textContent = text; status.setAttribute("data-tone", tone || ""); }

  function openFile(file) {
    if (!file) return;
    if (file.size > MAX_BYTES) { setStatus("That file is over 15 MB. Choose soc2-evidence/report.json.", "err"); return; }
    var reader = new FileReader();
    reader.onerror = function () { setStatus("The file couldn't be read. Try choosing it again.", "err"); };
    reader.onload = function () {
      var report;
      try {
        report = normalise(JSON.parse(String(reader.result)));
      } catch (e) {
        setStatus(e instanceof SyntaxError ? "That file isn't valid JSON. Choose soc2-evidence/report.json." : e.message, "err");
        return;
      }
      setStatus("Opened " + str(file.name, 80) + ". It stays in this browser tab.", "ok");
      buildSheet(report, false);
      $("board-progress").textContent = finalLine(report);
      render(report, "Your scan, read in this browser and not uploaded.");
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
        setTimeout(function () { btn.textContent = "Copy commands"; }, 1600);
      });
    });
  });
})();

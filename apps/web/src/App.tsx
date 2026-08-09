import { useEffect, useMemo, useRef, useState } from "react";

import {
  compareCorrelations,
  correlateReports,
  exportBaselineDiff,
  exportCorrelation,
  parseReport,
  severityOrder,
  type BaselineDiffItem,
  type FindingCluster,
  type MatchScope,
  type OutputFormat,
  type ReportInput,
  type Severity,
} from "@vulnfuse/core";

import { demoBaselineReports, demoReports } from "./demo.js";

const maxFileBytes = 100 * 1024 * 1024;
const accepted = ".json,.sarif,.csv,application/json,text/csv";
const severityFilters = ["all", "critical", "high", "medium", "low", "info", "unknown"] as const;

export function App() {
  const [inputs, setInputs] = useState<ReportInput[]>([]);
  const [baselineInputs, setBaselineInputs] = useState<ReportInput[]>([]);
  const [threshold, setThreshold] = useState(70);
  const [scope, setScope] = useState<MatchScope>("instance");
  const [selectedId, setSelectedId] = useState<string>();
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<(typeof severityFilters)[number]>("all");
  const [dropActive, setDropActive] = useState(false);
  const [fileError, setFileError] = useState<string>();
  const picker = useRef<HTMLInputElement>(null);
  const baselinePicker = useRef<HTMLInputElement>(null);

  const analysis = useMemo(() => {
    try {
      const reports = inputs.map((input) => parseReport(input));
      const result = correlateReports(reports, { threshold, scope });
      const baselineReports = baselineInputs.map((input) => parseReport(input));
      const baselineResult =
        baselineReports.length > 0
          ? correlateReports(baselineReports, { threshold, scope })
          : undefined;
      const diff = baselineResult ? compareCorrelations(baselineResult, result) : undefined;
      return { reports, baselineReports, result, diff, error: undefined };
    } catch (error) {
      return {
        reports: [],
        baselineReports: [],
        result: undefined,
        diff: undefined,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }, [baselineInputs, inputs, scope, threshold]);

  const baselineItemsByClusterId = useMemo(
    () =>
      new Map(
        (analysis.diff?.items ?? [])
          .filter((item) => item.state !== "absent")
          .map((item) => [item.cluster.id, item]),
      ),
    [analysis.diff],
  );

  const visibleClusters = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return (analysis.result?.clusters ?? []).filter((cluster) => {
      if (severityFilter !== "all" && cluster.severity !== severityFilter) return false;
      if (!normalizedQuery) return true;
      return [
        cluster.primary.title,
        ...cluster.identifiers.map((identifier) => identifier.value),
        cluster.primary.component?.name,
        cluster.primary.component?.purl,
        ...cluster.sourceTools,
        ...cluster.assets.map((asset) => asset.name),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(normalizedQuery);
    });
  }, [analysis.result, query, severityFilter]);

  useEffect(() => {
    if (!analysis.result) {
      setSelectedId(undefined);
      return;
    }
    if (!analysis.result.clusters.some((cluster) => cluster.id === selectedId)) {
      setSelectedId(analysis.result.clusters[0]?.id);
    }
  }, [analysis.result, selectedId]);

  const selected = analysis.result?.clusters.find((cluster) => cluster.id === selectedId);
  const selectedDiff = selectedId ? baselineItemsByClusterId.get(selectedId) : undefined;

  async function addFiles(files: FileList | File[]) {
    setFileError(undefined);
    const candidates = [...files];
    if (inputs.length + baselineInputs.length + candidates.length > 1_000) {
      setFileError("A maximum of 1,000 current and baseline reports can be processed at once.");
      return;
    }
    const oversized = candidates.find((file) => file.size > maxFileBytes);
    if (oversized) {
      setFileError(`${oversized.name} exceeds the 100 MiB per-file safety limit.`);
      return;
    }
    try {
      const next = await Promise.all(
        candidates.map(async (file) => ({ name: file.name, content: await file.text() })),
      );
      setInputs((current) => [...current, ...next]);
    } catch (error) {
      setFileError(error instanceof Error ? error.message : String(error));
    }
  }

  async function addBaselineFiles(files: FileList | File[]) {
    setFileError(undefined);
    const candidates = [...files];
    if (inputs.length + baselineInputs.length + candidates.length > 1_000) {
      setFileError("A maximum of 1,000 current and baseline reports can be processed at once.");
      return;
    }
    const oversized = candidates.find((file) => file.size > maxFileBytes);
    if (oversized) {
      setFileError(`${oversized.name} exceeds the 100 MiB per-file safety limit.`);
      return;
    }
    try {
      const next = await Promise.all(
        candidates.map(async (file) => ({ name: file.name, content: await file.text() })),
      );
      setBaselineInputs((current) => [...current, ...next]);
    } catch (error) {
      setFileError(error instanceof Error ? error.message : String(error));
    }
  }

  function download(format: OutputFormat) {
    if (!analysis.result) return;
    const extensions: Record<OutputFormat, string> = {
      json: "json",
      sarif: "sarif",
      csv: "csv",
      markdown: "md",
    };
    const blob = new Blob(
      [
        analysis.diff
          ? exportBaselineDiff(analysis.diff, format)
          : exportCorrelation(analysis.result, format),
      ],
      {
        type: "text/plain;charset=utf-8",
      },
    );
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `vulnfuse-${analysis.diff ? "baseline-diff" : "report"}.${extensions[format]}`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="VulnFuse home">
          <Logo />
          <span>VulnFuse</span>
          <span className="version">alpha · 0.2</span>
        </a>
        <nav aria-label="Project links">
          <a href="#workbench">Workbench</a>
          <a href="https://github.com/CAOShurong/vulnfuse">GitHub ↗</a>
        </nav>
      </header>

      <main id="top">
        <section className="hero">
          <div className="eyebrow">
            <span /> Local-first security evidence workbench
          </div>
          <h1>
            One vulnerability.
            <br />
            <em>Every piece of evidence.</em>
          </h1>
          <p className="hero-copy">
            Correlate duplicate findings from different scanners without pretending they agree.
            VulnFuse shows each match score, the blockers it detects, and every original source
            record.
          </p>
          <div className="hero-actions">
            <button className="primary" type="button" onClick={() => picker.current?.click()}>
              Add scanner reports
            </button>
            <button
              className="secondary"
              type="button"
              onClick={() => {
                setInputs(demoReports);
                setBaselineInputs(demoBaselineReports);
              }}
            >
              Load safe demo
            </button>
          </div>
          <div className="trust-row" aria-label="Privacy and capability notes">
            <span>
              <LockIcon /> Nothing leaves this tab
            </span>
            <span>
              <BranchIcon /> Evidence stays attributable
            </span>
            <span>
              <SparkIcon /> No AI or API key
            </span>
          </div>
        </section>

        <section className="format-rail" aria-label="Supported formats">
          <span>READS</span>
          {["SARIF 2.1", "Trivy", "Grype", "Snyk", "CycloneDX", "OSV", "CSV"].map((format) => (
            <b key={format}>{format}</b>
          ))}
        </section>

        <section className="workbench" id="workbench">
          <div className="workbench-head">
            <div>
              <span className="section-number">01</span>
              <h2>Bring the evidence together</h2>
              <p>
                Drop reports from separate tools. Parsing and correlation happen in your browser.
              </p>
            </div>
            {inputs.length > 0 && (
              <button className="text-button" type="button" onClick={() => setInputs([])}>
                Clear all
              </button>
            )}
          </div>

          <input
            ref={picker}
            className="visually-hidden"
            type="file"
            accept={accepted}
            multiple
            onChange={(event) => {
              if (event.target.files) void addFiles(event.target.files);
              event.target.value = "";
            }}
          />
          <input
            ref={baselinePicker}
            className="visually-hidden"
            type="file"
            accept={accepted}
            multiple
            onChange={(event) => {
              if (event.target.files) void addBaselineFiles(event.target.files);
              event.target.value = "";
            }}
          />

          <button
            className={`dropzone ${dropActive ? "active" : ""}`}
            type="button"
            onClick={() => picker.current?.click()}
            onDragEnter={(event) => {
              event.preventDefault();
              setDropActive(true);
            }}
            onDragOver={(event) => event.preventDefault()}
            onDragLeave={() => setDropActive(false)}
            onDrop={(event) => {
              event.preventDefault();
              setDropActive(false);
              void addFiles(event.dataTransfer.files);
            }}
          >
            <span className="drop-icon">
              <UploadIcon />
            </span>
            <strong>{dropActive ? "Release to add reports" : "Drop scanner reports here"}</strong>
            <small>JSON, SARIF, or CSV · up to 100 MiB each</small>
          </button>

          {(fileError || analysis.error) && (
            <div className="error-banner" role="alert">
              {fileError ?? analysis.error}
            </div>
          )}
          {inputs.length > 0 && (
            <div className="file-list" aria-label="Loaded reports">
              {inputs.map((input, index) => {
                const report = analysis.reports[index];
                return (
                  <div className="file-chip" key={`${input.name}-${index}`}>
                    <span className="file-mark">
                      {report?.format.slice(0, 2).toUpperCase() ?? "?"}
                    </span>
                    <span>
                      <strong>{input.name}</strong>
                      <small>
                        {report
                          ? `${report.tool} · ${report.findings.length} findings`
                          : "Waiting to parse"}
                      </small>
                    </span>
                    <button
                      type="button"
                      aria-label={`Remove ${input.name}`}
                      onClick={() =>
                        setInputs((current) =>
                          current.filter((_, itemIndex) => itemIndex !== index),
                        )
                      }
                    >
                      ×
                    </button>
                  </div>
                );
              })}
            </div>
          )}
          <div className={`baseline-loader ${baselineInputs.length > 0 ? "active" : ""}`}>
            <div>
              <strong>Optional baseline</strong>
              <small>
                Add reports from a previous run to label current clusters as new, updated, or
                unchanged, and to count findings that disappeared.
              </small>
            </div>
            <div className="baseline-actions">
              <button type="button" onClick={() => baselinePicker.current?.click()}>
                {baselineInputs.length > 0 ? "Add baseline reports" : "Choose baseline reports"}
              </button>
              {baselineInputs.length > 0 && (
                <button className="text-button" type="button" onClick={() => setBaselineInputs([])}>
                  Clear baseline
                </button>
              )}
            </div>
          </div>
          {baselineInputs.length > 0 && (
            <div className="file-list baseline-files" aria-label="Loaded baseline reports">
              {baselineInputs.map((input, index) => {
                const report = analysis.baselineReports[index];
                return (
                  <div className="file-chip" key={`baseline-${input.name}-${index}`}>
                    <span className="file-mark baseline">B</span>
                    <span>
                      <strong>{input.name}</strong>
                      <small>
                        {report
                          ? `${report.tool} · ${report.findings.length} baseline findings`
                          : "Waiting to parse"}
                      </small>
                    </span>
                    <button
                      type="button"
                      aria-label={`Remove baseline ${input.name}`}
                      onClick={() =>
                        setBaselineInputs((current) =>
                          current.filter((_, itemIndex) => itemIndex !== index),
                        )
                      }
                    >
                      ×
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        {analysis.result && analysis.result.summary.inputFindings > 0 && (
          <section className="results-section">
            <div className="workbench-head">
              <div>
                <span className="section-number">02</span>
                <h2>Review the correlation</h2>
                <p>Tune the policy, inspect each merge, then export a reviewable artifact.</p>
              </div>
              <ExportMenu onExport={download} />
            </div>

            <div className="control-strip">
              <label className="threshold-control">
                <span>
                  Match threshold <strong>{threshold}</strong>
                </span>
                <input
                  type="range"
                  min="40"
                  max="100"
                  value={threshold}
                  onChange={(event) => setThreshold(Number(event.target.value))}
                />
                <small>Higher means fewer, stricter merges.</small>
              </label>
              <div className="scope-control">
                <span>Correlation scope</span>
                <div className="segmented">
                  <button
                    className={scope === "instance" ? "selected" : ""}
                    type="button"
                    onClick={() => setScope("instance")}
                  >
                    Same asset
                  </button>
                  <button
                    className={scope === "root-cause" ? "selected" : ""}
                    type="button"
                    onClick={() => setScope("root-cause")}
                  >
                    Root cause
                  </button>
                </div>
                <small>
                  {scope === "instance"
                    ? "Different assets stay separate."
                    : "The same vulnerable component may span assets."}
                </small>
              </div>
            </div>

            <SummaryCards result={analysis.result} />
            {analysis.diff && <BaselineSummary diff={analysis.diff} />}

            <div className="result-grid">
              <div className="cluster-browser">
                <div className="browser-tools">
                  <label className="search">
                    <SearchIcon />
                    <input
                      value={query}
                      onChange={(event) => setQuery(event.target.value)}
                      placeholder="Search CVE, package, asset…"
                    />
                  </label>
                  <select
                    aria-label="Filter by severity"
                    value={severityFilter}
                    onChange={(event) =>
                      setSeverityFilter(event.target.value as typeof severityFilter)
                    }
                  >
                    {severityFilters.map((severity) => (
                      <option key={severity} value={severity}>
                        {severity === "all" ? "All severities" : severity}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="cluster-count">
                  {visibleClusters.length} of {analysis.result.summary.clusters} clusters
                </div>
                <div className="cluster-list">
                  {visibleClusters.map((cluster) => (
                    <button
                      className={`cluster-row ${selectedId === cluster.id ? "selected" : ""}`}
                      key={cluster.id}
                      type="button"
                      onClick={() => setSelectedId(cluster.id)}
                    >
                      <span className={`severity-dot ${cluster.severity}`} />
                      <span className="cluster-copy">
                        <strong>{cluster.primary.title}</strong>
                        <small>
                          {cluster.identifiers[0]?.value ??
                            cluster.primary.component?.name ??
                            "No advisory ID"}
                          {analysis.diff && (
                            <b
                              className={`baseline-state ${baselineItemsByClusterId.get(cluster.id)?.state ?? "new"}`}
                            >
                              {baselineItemsByClusterId.get(cluster.id)?.state ?? "new"}
                            </b>
                          )}
                        </small>
                      </span>
                      <span className="source-stack">
                        {cluster.sourceTools.slice(0, 3).map((tool) => (
                          <i key={tool} title={tool}>
                            {tool.slice(0, 1).toUpperCase()}
                          </i>
                        ))}
                      </span>
                      <span className="member-count">{cluster.members.length}×</span>
                    </button>
                  ))}
                  {visibleClusters.length === 0 && (
                    <div className="empty-filter">No clusters match this filter.</div>
                  )}
                </div>
              </div>
              <ClusterDetail
                cluster={selected}
                baselineItem={selectedDiff}
                rejectedCandidates={analysis.result.rejectedCandidates}
              />
            </div>
          </section>
        )}

        <section className="principles">
          <span className="section-number">03</span>
          <h2>
            Correlation is a claim.
            <br />
            VulnFuse shows its work.
          </h2>
          <div className="principle-grid">
            <article>
              <b>01</b>
              <h3>Deterministic</h3>
              <p>
                The same inputs and policy produce the same cluster IDs and output. No model drift,
                hidden service, or API dependency.
              </p>
            </article>
            <article>
              <b>02</b>
              <h3>Conservative</h3>
              <p>
                Conflicting CVE, component, asset, or finding-kind evidence blocks a merge instead
                of being silently averaged away.
              </p>
            </article>
            <article>
              <b>03</b>
              <h3>Auditable</h3>
              <p>
                Every cluster retains its source records, match edges, scores, reasons, identifiers,
                locations, and remediation.
              </p>
            </article>
          </div>
        </section>
      </main>

      <footer>
        <Logo />
        <span>VulnFuse · Apache-2.0</span>
        <span>Reports stay in your browser.</span>
      </footer>
    </div>
  );
}

function SummaryCards({ result }: { result: NonNullable<ReturnType<typeof correlateReports>> }) {
  const duplicateRate =
    result.summary.inputFindings === 0
      ? 0
      : Math.round((result.summary.duplicatesCollapsed / result.summary.inputFindings) * 100);
  return (
    <div className="summary-cards">
      <article>
        <span>Source findings</span>
        <strong>{result.summary.inputFindings}</strong>
        <small>from {result.summary.sourceTools.length} tools</small>
      </article>
      <article className="accent">
        <span>Correlated clusters</span>
        <strong>{result.summary.clusters}</strong>
        <small>{duplicateRate}% duplicate records</small>
      </article>
      <article>
        <span>Records collapsed</span>
        <strong>{result.summary.duplicatesCollapsed}</strong>
        <small>nothing discarded</small>
      </article>
      <article className="severity-card">
        <span>Cluster severity</span>
        <SeverityBar counts={result.summary.bySeverity} />
        <small>
          {result.summary.bySeverity.critical} critical · {result.summary.bySeverity.high} high
        </small>
      </article>
    </div>
  );
}

function BaselineSummary({ diff }: { diff: NonNullable<ReturnType<typeof compareCorrelations>> }) {
  const cards = [
    ["new", diff.summary.new, "not present before"],
    ["updated", diff.summary.updated, "matched, evidence changed"],
    ["absent", diff.summary.absent, "missing from this run"],
    ["unchanged", diff.summary.unchanged, "stable across runs"],
  ] as const;
  return (
    <div className="baseline-summary" aria-label="Baseline comparison summary">
      {cards.map(([state, count, note]) => (
        <article className={state} key={state}>
          <span>{state}</span>
          <strong>{count}</strong>
          <small>{note}</small>
        </article>
      ))}
    </div>
  );
}

function SeverityBar({ counts }: { counts: Record<Severity, number> }) {
  const total = Object.values(counts).reduce((sum, count) => sum + count, 0) || 1;
  return (
    <div className="severity-bar" aria-label="Severity distribution">
      {severityOrder.map(
        (severity) =>
          counts[severity] > 0 && (
            <span
              key={severity}
              className={severity}
              style={{ width: `${(counts[severity] / total) * 100}%` }}
              title={`${severity}: ${counts[severity]}`}
            />
          ),
      )}
    </div>
  );
}

function ClusterDetail({
  cluster,
  baselineItem,
  rejectedCandidates,
}: {
  cluster: FindingCluster | undefined;
  baselineItem: BaselineDiffItem | undefined;
  rejectedCandidates: ReturnType<typeof correlateReports>["rejectedCandidates"];
}) {
  if (!cluster)
    return (
      <aside className="cluster-detail empty">
        <ShieldIcon />
        <p>Select a cluster to inspect the evidence.</p>
      </aside>
    );
  const reasons = cluster.edges.flatMap((edge) => edge.explanation.reasons);
  const memberIds = new Set(cluster.members.map((member) => member.id));
  const blockers = rejectedCandidates
    .filter((edge) => memberIds.has(edge.leftId) || memberIds.has(edge.rightId))
    .flatMap((edge) => edge.explanation.blockers)
    .filter(
      (blocker, index, all) =>
        all.findIndex(
          (item) => item.feature === blocker.feature && item.message === blocker.message,
        ) === index,
    );
  return (
    <aside className="cluster-detail">
      <div className="detail-head">
        <span className={`severity-pill ${cluster.severity}`}>{cluster.severity}</span>
        <code>{cluster.id}</code>
      </div>
      {baselineItem && (
        <div className={`baseline-detail ${baselineItem.state}`}>
          <strong>{baselineItem.state}</strong>
          <span>
            {baselineItem.changedFields.length > 0
              ? `Changed: ${baselineItem.changedFields.join(", ")}`
              : baselineItem.state === "new"
                ? "No matching baseline cluster."
                : `Matched baseline at ${baselineItem.explanation?.score ?? 100}/100.`}
          </span>
        </div>
      )}
      <h3>{cluster.primary.title}</h3>
      {cluster.primary.description && <p className="description">{cluster.primary.description}</p>}
      <dl className="fact-grid">
        <div>
          <dt>Identifiers</dt>
          <dd>
            {cluster.identifiers.length
              ? cluster.identifiers.map((identifier) => (
                  <span className="tag" key={`${identifier.scheme}-${identifier.value}`}>
                    {identifier.value}
                  </span>
                ))
              : "—"}
          </dd>
        </div>
        <div>
          <dt>Component</dt>
          <dd className="mono">
            {cluster.primary.component?.purl ?? cluster.primary.component?.name ?? "—"}
          </dd>
        </div>
        <div>
          <dt>Assets</dt>
          <dd>{cluster.assets.map((item) => item.name).join(", ") || "—"}</dd>
        </div>
        <div>
          <dt>Fix</dt>
          <dd>
            {cluster.primary.remediation?.fixedVersion ??
              cluster.primary.remediation?.recommendation ??
              "Not supplied"}
          </dd>
        </div>
      </dl>
      <section className="evidence-section">
        <div className="subhead">
          <h4>
            Why {cluster.members.length > 1 ? "these records merged" : "this stayed separate"}
          </h4>
          <span>{cluster.confidence} confidence</span>
        </div>
        {reasons.length > 0 ? (
          <div className="reason-list">
            {reasons.map((reason, index) => (
              <div className="reason" key={`${reason.feature}-${index}`}>
                <span>+{reason.score}</span>
                <p>
                  <strong>{reason.feature}</strong>
                  {reason.message}
                </p>
              </div>
            ))}
          </div>
        ) : (
          <p className="muted">A single source record needs no merge claim.</p>
        )}
      </section>
      {blockers.length > 0 && (
        <section className="evidence-section">
          <div className="subhead">
            <h4>Why nearby candidates stayed separate</h4>
            <span>{blockers.length} blockers</span>
          </div>
          <div className="blocker-list">
            {blockers.map((blocker) => (
              <div className="blocker" key={`${blocker.feature}-${blocker.message}`}>
                <span>×</span>
                <p>
                  <strong>{blocker.feature}</strong>
                  {blocker.message}
                </p>
              </div>
            ))}
          </div>
        </section>
      )}
      <section className="evidence-section">
        <div className="subhead">
          <h4>Source records</h4>
          <span>{cluster.members.length}</span>
        </div>
        <div className="member-list">
          {cluster.members.map((member) => (
            <article key={member.id}>
              <span className="tool-badge">{member.source.tool.slice(0, 2).toUpperCase()}</span>
              <div>
                <strong>{member.source.tool}</strong>
                <small>{member.source.report}</small>
              </div>
              <span className={`mini-severity ${member.severity}`}>{member.severity}</span>
            </article>
          ))}
        </div>
      </section>
      {cluster.primary.references.length > 0 && (
        <a
          className="reference-link"
          href={cluster.primary.references[0]}
          target="_blank"
          rel="noreferrer"
        >
          Open primary advisory ↗
        </a>
      )}
    </aside>
  );
}

function ExportMenu({ onExport }: { onExport: (format: OutputFormat) => void }) {
  return (
    <div className="export-menu">
      <span>Export</span>
      {(["sarif", "json", "csv", "markdown"] as OutputFormat[]).map((format) => (
        <button type="button" key={format} onClick={() => onExport(format)}>
          {format === "markdown" ? "MD" : format.toUpperCase()}
        </button>
      ))}
    </div>
  );
}

function Logo() {
  return (
    <svg className="logo" viewBox="0 0 40 40" aria-hidden="true">
      <path d="M20 3 34 9v10c0 8.9-5.6 14.9-14 18-8.4-3.1-14-9.1-14-18V9l14-6Z" />
      <path d="m12 20 5 5 11-12" />
    </svg>
  );
}
function LockIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <rect x="5" y="10" width="14" height="10" rx="2" />
      <path d="M8 10V7a4 4 0 0 1 8 0v3" />
    </svg>
  );
}
function BranchIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="6" cy="5" r="2" />
      <circle cx="18" cy="7" r="2" />
      <circle cx="6" cy="19" r="2" />
      <path d="M6 7v10M8 13h3a7 7 0 0 0 7-4" />
    </svg>
  );
}
function SparkIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="m12 2 1.7 6.3L20 10l-6.3 1.7L12 18l-1.7-6.3L4 10l6.3-1.7L12 2Z" />
      <path d="m19 16 .7 2.3L22 19l-2.3.7L19 22l-.7-2.3L16 19l2.3-.7L19 16Z" />
    </svg>
  );
}
function UploadIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 16V4m0 0L7 9m5-5 5 5" />
      <path d="M5 14v5h14v-5" />
    </svg>
  );
}
function SearchIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="11" cy="11" r="6" />
      <path d="m16 16 4 4" />
    </svg>
  );
}
function ShieldIcon() {
  return (
    <svg viewBox="0 0 40 40" aria-hidden="true">
      <path d="M20 3 34 9v10c0 8.9-5.6 14.9-14 18-8.4-3.1-14-9.1-14-18V9l14-6Z" />
      <path d="M20 11v11m0 5v1" />
    </svg>
  );
}

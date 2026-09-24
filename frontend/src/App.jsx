import { useEffect, useState } from "react";

const SAMPLE = "Quarterly report: contact jane@example.com or 555-123-4567. SSN 123-45-6789.";
const API_URL = "http://127.0.0.1:8765/v1/redact";
const WORKER_URL = "http://127.0.0.1:8765";

async function apiFetch(url, options = {}) {
  let token = window.localStorage.getItem("local-redaction-token");
  if (!token) {
    const tokenResponse = await fetch(`${WORKER_URL}/dev/token`);
    if (tokenResponse.ok) {
      token = (await tokenResponse.json()).token;
      window.localStorage.setItem("local-redaction-token", token);
    }
  }
  const headers = new Headers(options.headers || {});
  if (token) headers.set("X-Local-Token", token);
  return fetch(url, { ...options, headers });
}

export default function App() {
  const [text, setText] = useState(SAMPLE);
  const [profile, setProfile] = useState("placeholders");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);
  const [jobs, setJobs] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [view, setView] = useState("redact");
  const [profiles, setProfiles] = useState([]);
  const [ruleProfileName, setRuleProfileName] = useState("healthcare_standard");
  const [customRule, setCustomRule] = useState({ name: "MEDICAL_RECORD_NUM", type: "regex", pattern: "MRN-\\d{4}-\\s?\\d{4}", words: "", strategy: "placeholder" });
  const [builtinEnabled, setBuiltinEnabled] = useState({ EMAIL: true, PHONE: true, SSN: true, CREDIT_CARD: true, IP_ADDRESS: true, DATE_OF_BIRTH: true, API_KEY: true });

  async function loadJobs() {
    const response = await apiFetch(`${WORKER_URL}/v1/jobs`);
    if (response.ok) setJobs(await response.json());
  }

  useEffect(() => { loadJobs().catch(() => {}); }, []);
  useEffect(() => { apiFetch(`${WORKER_URL}/v1/profiles`).then((response) => response.ok ? response.json() : []).then(setProfiles).catch(() => {}); }, []);

  async function saveProfile(event) {
    event.preventDefault();
    setError("");
    const rule = { name: customRule.name, type: customRule.type, strategy: customRule.strategy, confidence: 1.0 };
    if (customRule.type === "regex") rule.pattern = customRule.pattern;
    if (customRule.type === "dictionary") rule.words = customRule.words.split(",").map((word) => word.trim()).filter(Boolean);
    if (customRule.type === "context_word") rule.anchor_words = customRule.words.split(",").map((word) => word.trim()).filter(Boolean);
    const body = { profile_name: ruleProfileName, builtin_entities: Object.fromEntries(Object.entries(builtinEnabled).map(([name, enabled]) => [name, { enabled, strategy: "placeholder" }])), custom_entities: [rule] };
    const response = await apiFetch(`${WORKER_URL}/v1/profiles`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (!response.ok) { const detail = await response.json().catch(() => ({})); setError(detail.detail || "Profile could not be saved"); return; }
    const saved = await response.json();
    setProfiles((current) => [...current.filter((item) => (item.profile_name || item.id) !== saved.profile_name), saved]);
    setProfile(saved.profile_name);
    setView("redact");
  }

  async function handleRedact() {
    setIsProcessing(true);
    setError("");
    try {
      const response = await apiFetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, profile, source_name: "console-input.txt" }),
      });
      if (!response.ok) throw new Error(`Worker returned ${response.status}`);
      const createdJob = await response.json();
      const detail = await apiFetch(`${WORKER_URL}/v1/jobs/${createdJob.job_id}`);
      setResult(detail.ok ? await detail.json() : createdJob);
      await loadJobs();
    } catch (requestError) {
      setError(`${requestError.message}. Start the FastAPI worker on 127.0.0.1:8765.`);
    } finally {
      setIsProcessing(false);
    }
  }

  async function handleFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    setSelectedFile(file);
    setIsProcessing(true);
    setError("");
    try {
      const form = new FormData();
      form.append("file", file);
      const response = await apiFetch(`${WORKER_URL}/v1/files?profile=${profile}`, { method: "POST", body: form });
      if (!response.ok) throw new Error(`Worker returned ${response.status}`);
      const createdJob = await response.json();
      const detail = await apiFetch(`${WORKER_URL}/v1/jobs/${createdJob.job_id}`);
      setResult(detail.ok ? await detail.json() : createdJob);
      await loadJobs();
    } catch (requestError) {
      setError(`${requestError.message}. Check the file type and worker status.`);
    } finally { setIsProcessing(false); }
  }

  async function openJob(jobId) {
    const response = await apiFetch(`${WORKER_URL}/v1/jobs/${jobId}`);
    if (response.ok) setResult(await response.json());
  }

  async function reviewEntity(tokenIndex, decision) {
    if (!result?.job_id && !result?.id) return;
    const jobId = result.job_id || result.id;
    const response = await apiFetch(`${WORKER_URL}/v1/jobs/${jobId}/entities/${tokenIndex}`, {
      method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ decision }),
    });
    if (response.ok) { setResult(await response.json()); await loadJobs(); }
  }

  async function deleteCurrentJob() {
    const jobId = result?.job_id || result?.id;
    if (!jobId) return;
    const response = await apiFetch(`${WORKER_URL}/v1/jobs/${jobId}`, { method: "DELETE" });
    if (response.ok) { setResult(null); await loadJobs(); }
  }

  return (
    <main className="shell">
      <header className="topbar">
        <div className="brand-mark">LR</div>
        <div>
          <p className="eyebrow">PRIVATE NETWORK / GATEWAY 01</p>
          <h1>Local Redaction Console</h1>
        </div>
        <div className="status"><span /> Worker loopback only</div>
      </header>

      <nav className="view-tabs"><button className={view === "redact" ? "active" : ""} onClick={() => setView("redact")}>Redaction workspace</button><button className={view === "rules" ? "active" : ""} onClick={() => setView("rules")}>Rules manager</button></nav>

      {view === "rules" ? <section className="panel rules-panel">
        <div className="panel-heading"><span>POLICY BUILDER</span><span className="quiet">LOCAL CONFIGURATION</span></div>
        <form className="rules-form" onSubmit={saveProfile}>
          <label>Profile name<input value={ruleProfileName} onChange={(event) => setRuleProfileName(event.target.value)} /></label>
          <div className="builtin-grid">{Object.keys(builtinEnabled).map((name) => <label className="check-row" key={name}><input type="checkbox" checked={builtinEnabled[name]} onChange={(event) => setBuiltinEnabled({ ...builtinEnabled, [name]: event.target.checked })} />{name}</label>)}</div>
          <label>Custom rule name<input value={customRule.name} onChange={(event) => setCustomRule({ ...customRule, name: event.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, "_") })} /></label>
          <label>Rule type<select value={customRule.type} onChange={(event) => setCustomRule({ ...customRule, type: event.target.value })}><option value="regex">Regex matcher</option><option value="dictionary">Keyword dictionary</option><option value="context_word">Context word</option></select></label>
          <label>{customRule.type === "regex" ? "Pattern" : customRule.type === "dictionary" ? "Words, comma separated" : "Anchor words, comma separated"}<input value={customRule.type === "regex" ? customRule.pattern : customRule.words} onChange={(event) => setCustomRule({ ...customRule, [customRule.type === "regex" ? "pattern" : "words"]: event.target.value })} /></label>
          <label>Replacement<select value={customRule.strategy} onChange={(event) => setCustomRule({ ...customRule, strategy: event.target.value })}><option value="placeholder">Placeholder</option><option value="redact">Mask</option></select></label>
          <button type="submit">Save profile locally <span>↗</span></button>
        </form>
        {profiles.filter((item) => item.profile_name).map((item) => <div className="saved-profile" key={item.profile_name}><strong>{item.profile_name}</strong><span>{item.custom_entities?.length || 0} custom rules</span></div>)}
      </section> : <>

      <section className="intro">
        <div>
          <p className="eyebrow warm">PII SAFETY WORKBENCH</p>
          <h2>Clear sensitive data before it leaves the room.</h2>
          <p className="lede">A deterministic first pass for emails, phone numbers, SSNs, and payment data. The original payload stays local.</p>
        </div>
        <div className="metric"><strong>{result?.entities.length ?? 0}</strong><span>entities found</span></div>
        <div className="metric"><strong>{result ? `${result.processing_ms}ms` : "--"}</strong><span>last pass</span></div>
      </section>

      <section className="workspace">
        <div className="panel input-panel">
          <div className="panel-heading"><span>01 / SOURCE PAYLOAD</span><span className="quiet">TEXT INPUT</span></div>
          <textarea value={text} onChange={(event) => setText(event.target.value)} aria-label="Source payload" />
          <div className="controls">
            <label>Redaction profile
              <select value={profile} onChange={(event) => setProfile(event.target.value)}>
                <option value="placeholders">Stable placeholders</option>
                <option value="full_masking">Full masking</option>
                {profiles.filter((item) => item.profile_name).map((item) => <option value={item.profile_name} key={item.profile_name}>{item.profile_name}</option>)}
              </select>
            </label>
            <button onClick={handleRedact} disabled={isProcessing || !text.trim()}>{isProcessing ? "Processing..." : "Redact locally"}<span>↗</span></button>
          </div>
          <label className="file-picker">Or inspect a file
            <input type="file" accept=".txt,.md,.log,.eml,.csv,.json,.pdf,.docx" onChange={handleFile} />
            <span>{selectedFile?.name || "Choose PDF, DOCX, CSV, JSON, or text"}</span>
          </label>
        </div>

        <div className="panel output-panel">
          <div className="panel-heading"><span>02 / SAFE OUTPUT</span><span className="quiet">CLOUD-READY COPY</span></div>
          <div className="review-columns">
            <div><small>LOCAL SOURCE</small><div className="output-text">{result?.source_text || text}</div></div>
            <div><small>SAFE OUTPUT</small><div className="output-text">{result?.redacted_text || <span className="placeholder">Your redacted payload will appear here.</span>}</div></div>
          </div>
          {error && <p className="error">{error}</p>}
          {result && <div className="risk-row"><span>Risk score</span><strong>{Math.round(result.risk_score * 100)}%</strong><span className="review-status">{result.status}</span><a className="download" href={`http://127.0.0.1:8765/v1/jobs/${result.job_id || result.id}/download`}>Download safe copy ↓</a><button className="delete-button" onClick={deleteCurrentJob}>Delete local job</button><div className="risk-bar"><i style={{ width: `${result.risk_score * 100}%` }} /></div></div>}
        </div>
      </section>

      <section className="panel ledger-panel">
        <div className="panel-heading"><span>03 / DETECTION LEDGER</span><span className="quiet">HASHED VALUES ONLY</span></div>
        {result?.entities.length ? result.entities.map((entity) => (
          <div className="ledger-row" key={`${entity.entity_type}-${entity.token_index}`}>
            <span className="tag">{entity.entity_type}</span><code>{entity.replacement}</code><span className="hash">{entity.original_hash.slice(0, 24)}...</span><span className="confidence">{Math.round(entity.confidence * 100)}%</span><span className="entity-status">{entity.review_status || "pending"}</span><button className="review-button" onClick={() => reviewEntity(entity.token_index, entity.review_status === "approved" ? "rejected" : "approved")}>{entity.review_status === "approved" ? "Reject" : "Approve"}</button>
          </div>
        )) : <p className="empty">No detection events yet. Submit a payload to populate the local audit view.</p>}
      </section>

      <section className="panel history-panel">
        <div className="panel-heading"><span>04 / LOCAL JOB HISTORY</span><span className="quiet">LAST 50 JOBS</span></div>
        {jobs.length ? jobs.map((job) => <button className="history-row" key={job.id} onClick={() => openJob(job.id)}><span>{job.source_name}</span><span>{job.entity_count} entities</span><span className={`history-status ${job.status}`}>{job.status}</span></button>) : <p className="empty">Completed jobs will remain available locally for review.</p>}
      </section>
      </>}
    </main>
  );
}

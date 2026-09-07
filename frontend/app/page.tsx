"use client";

import { useState } from "react";

type Session = { session_id: string; protocol: string; transition: string; tls_version: string; risk_score: number; confidence: string; anomaly_score: number | null; anomaly_status: string };
type Finding = { session: string; severity: string; rule: string; title: string; evidence: string };
type Report = { sha256: string; packet_count: number; sessions: Session[]; findings: Finding[] };
const API = "http://127.0.0.1:8000";

export default function Home() {
  const [file, setFile] = useState<File | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [message, setMessage] = useState("Ready for a real PCAP.");
  const [busy, setBusy] = useState(false);

  async function send(endpoint: string, json = false) {
    if (!file) { setMessage("Choose a PCAP file first."); return; }
    setBusy(true); setMessage(json ? "Creating JSON report…" : "Analysing capture…");
    const form = new FormData(); form.append("file", file);
    try {
      const response = await fetch(`${API}${endpoint}`, { method: "POST", body: form });
      if (!response.ok) { const data = await response.json().catch(() => null); throw new Error(data?.detail || "Request failed."); }
      if (json) {
        const blob = await response.blob(); const url = URL.createObjectURL(blob); const link = document.createElement("a");
        link.href = url; link.download = `${file.name.replace(/\.[^.]+$/, "")}-securemailscope-report.json`; link.click(); URL.revokeObjectURL(url);
        setMessage("JSON report downloaded.");
      } else { setReport(await response.json()); setMessage("Analysis complete."); }
    } catch (error) { setMessage(error instanceof Error ? error.message : "Request failed."); }
    finally { setBusy(false); }
  }

  const sessions = report ? [...report.sessions].sort((a, b) => b.risk_score - a.risk_score) : [];
  return <main>
    <header><p>SECUREMAILSCOPE / V0.5</p><h1>Evidence, not<br /><i>assumptions.</i></h1><span>Dual-engine PCAP analysis + bounded ML</span></header>
    <section className="upload">
      <div><b>Upload network capture</b><small>PCAP, PCAPNG, CAP · max 50 MB</small></div>
      <input id="capture" type="file" accept=".pcap,.pcapng,.cap" onChange={(event) => { setFile(event.target.files?.[0] ?? null); setReport(null); }} />
      <label htmlFor="capture">{file?.name ?? "Choose capture"}</label>
      <div className="actions"><button disabled={busy} onClick={() => send("/api/analyse")}>{busy ? "Working…" : "Analyse →"}</button><button className="secondary" disabled={busy} onClick={() => send("/api/report/json", true)}>Download JSON report</button></div>
      <small>{message}</small>
    </section>
    {report && <>
      <section className="metrics"><Card name="Packets" value={report.packet_count} /><Card name="Sessions" value={sessions.length} /><Card name="Top risk" value={`${sessions[0]?.risk_score ?? 0}/100`} /><Card name="Anomalies" value={sessions.filter((session) => session.anomaly_status === "ANOMALOUS").length} /></section>
      <section><p>HIGHEST-RISK SESSIONS</p><h2>Analyst priority</h2>{sessions.map((session) => <article key={session.session_id}><b className={session.risk_score >= 80 ? "CRITICAL" : session.risk_score >= 50 ? "HIGH" : ""}>{session.risk_score}/100</b><div><code>{session.confidence} confidence · {session.anomaly_status}{session.anomaly_score !== null ? ` · ML ${session.anomaly_score}` : ""}</code><h3>{session.protocol} / {session.transition}</h3><small>{session.session_id}</small></div></article>)}</section>
      <section><p>FINDINGS</p>{report.findings.length ? report.findings.map((finding) => <article key={finding.rule + finding.session}><b className={finding.severity}>{finding.severity}</b><div><h3>{finding.title}</h3><small>{finding.evidence}</small></div></article>) : <small>No deterministic alerts generated.</small>}</section>
      <section><p>CANONICAL SESSIONS</p><table><thead><tr><th>Protocol</th><th>Transition</th><th>TLS</th><th>Risk</th><th>Confidence</th><th>Anomaly</th></tr></thead><tbody>{sessions.map((session) => <tr key={session.session_id}><td>{session.protocol}</td><td>{session.transition}</td><td>{session.tls_version}</td><td>{session.risk_score}/100</td><td>{session.confidence}</td><td>{session.anomaly_status}{session.anomaly_score !== null ? ` (${session.anomaly_score})` : ""}</td></tr>)}</tbody></table></section>
      <footer><b>SHA-256</b><code>{report.sha256}</code></footer>
    </>}
  </main>;
}

function Card({ name, value }: { name: string; value: string | number }) { return <div className="card"><small>{name}</small><strong>{value}</strong></div>; }

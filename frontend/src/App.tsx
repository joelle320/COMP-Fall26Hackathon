import EnterpriseConsole from './EnterpriseConsole';
import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react';
import {
  Activity, ArrowDownToLine, ArrowRight, ArrowUpRight, Bell, Bot, Braces, Check,
  CheckCheck, CheckCircle2, ChevronDown, ChevronRight, Clock3, Code2, Copy,
  FileCheck2, Fingerprint, GitBranch, KeyRound, LayoutDashboard, ListFilter,
  LoaderCircle, LockKeyhole, Menu, Play, Plus, RefreshCw,
  Search, Settings2, Shield, ShieldAlert, ShieldCheck, SlidersHorizontal,
  TerminalSquare, TriangleAlert, UserRound, Workflow, X, XCircle,
} from 'lucide-react';

type Event = {
  id: string; timestamp: string; agent_id: string; session_id: string; event_type: string;
  requested_action: Record<string, unknown>; policy_violated: string[]; risk_level: number;
  decision: string; explanation: string; safe_alternative: string; alert_status: string;
  remediation_status: string; correlation_id: string; latency_ms: number; executed: boolean; execution_status?: string;
  findings?: Array<{ module: string; rule_id: string; risk_level: number; explanation: string }>;
  reviews?: Array<{ reviewer: string; note: string; timestamp: string }>;
};
type Session = { id: string; agent_id: string; role: string; capabilities: string[]; status: string; parent_session_id?: string; expires_at?: string };
type Approval = { id: string; status: string; session_id?: string; kind?: string; type?: string; remediation_id?: string; request?: unknown; requested_action?: unknown; expires_at?: string; created_at?: string; consumed?: boolean; [key: string]: unknown };
type Remediation = { id: string; session_id: string; status: string; stage?: string; approval_id?: string; original_capabilities?: string[]; proposed_capabilities?: string[]; recommended_capabilities?: string[]; validation?: unknown; [key: string]: unknown };
type State = {
  agents: Session[]; events: Event[]; incidents: Event[]; approvals: Approval[];
  remediations: Remediation[]; alerts: Array<Record<string, unknown>>;
  health: { status?: string; audit_valid?: boolean; enforcement_scope?: unknown; [key: string]: unknown };
  metrics: Record<string, unknown>; policy: Record<string, unknown>;
};
type DemoResult = { scenario: string; passed?: boolean; steps?: Array<{ title: string; result?: unknown }>; [key: string]: unknown };
type View = 'command' | 'accountwatch' | 'overview' | 'activity' | 'agents' | 'approvals' | 'incidents' | 'policy';
type Confirmation = { title: string; description: string; actionLabel: string; requireNote?: boolean; danger?: boolean; evidence?: unknown; action: (note: string) => Promise<void> };

const EMPTY: State = { agents: [], events: [], incidents: [], approvals: [], remediations: [], alerts: [], health: {}, metrics: {}, policy: {} };
const riskLabels = ['Informational', 'Low', 'Moderate', 'High', 'Critical'];
const riskColors = ['#8eaddb', '#a8efae', '#e9cf85', '#f4a57d', '#f17e8c'];
const nav = [
  { id: 'command', label: 'SENTINEL Command', icon: LayoutDashboard },
  { id: 'accountwatch', label: 'AccountWatch', icon: UserRound },
  { id: 'overview', label: 'AgentGuard overview', icon: ShieldCheck },
  { id: 'activity', label: 'Activity stream', icon: Activity },
  { id: 'agents', label: 'Protected agents', icon: Bot },
  { id: 'approvals', label: 'Human approvals', icon: FileCheck2 },
  { id: 'incidents', label: 'Incident log', icon: ShieldAlert },
  { id: 'policy', label: 'Policy & integrations', icon: SlidersHorizontal },
] as const;
const scenarios = [
  { id: 'a', name: 'Prompt injection', label: 'UNTRUSTED CONTEXT', description: 'Intercept an instruction override hidden in a repository document.', icon: Braces, color: 'blue' },
  { id: 'b', name: 'Credential exfiltration', label: 'DATA PROTECTION', description: 'Block a synthetic secret before it reaches an external destination.', icon: KeyRound, color: 'rose' },
  { id: 'c', name: 'Excessive permissions', label: 'LEAST PRIVILEGE', description: 'Propose a narrower configuration for an overprivileged agent.', icon: Fingerprint, color: 'amber' },
  { id: 'd', name: 'Compromised delegate', label: 'DELEGATION BOUNDARY', description: 'Isolate a delegated session that attempts an unauthorized action.', icon: GitBranch, color: 'purple' },
  { id: 'e', name: 'Detection misses. Policy holds.', label: 'RESOURCE AUTHORIZATION', description: 'Compare normal, flagged, and simulated missed detection against account-level access rules.', icon: ShieldCheck, color: 'blue' },
];

function shortId(value: string | undefined) { return value ? value.slice(0, 8) : '—'; }
function human(value: unknown) { return String(value ?? 'unknown').replaceAll('_', ' ').replaceAll('-', ' '); }
function fmtTime(value: string) { const d = new Date(value); return Number.isNaN(d.getTime()) ? '—' : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }); }
function fmtDate(value: string) { const d = new Date(value); return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString(); }
function titleCase(value: unknown) { const text = human(value); return text.charAt(0).toUpperCase() + text.slice(1); }
function statusOf(record: { status?: string; stage?: string }) { return String(record.status || record.stage || 'proposed').toLowerCase(); }
function pendingApproval(a: Approval) { return ['pending', 'proposed', 'awaiting_approval', 'requested'].includes(statusOf(a)); }
function formatJson(value: unknown) { return JSON.stringify(value, null, 2); }
function normalizeState(value: Partial<State>): State { return { ...EMPTY, ...value, agents: value.agents || [], events: value.events || [], incidents: value.incidents || [], approvals: value.approvals || [], remediations: value.remediations || [], alerts: value.alerts || [], health: value.health || {}, metrics: value.metrics || {}, policy: value.policy || {} }; }
function approvalEvidence(approval: Approval, remediations: Remediation[]) {
  const plan = remediations.find(item => item.id === approval.remediation_id || item.approval_id === approval.id);
  return {
    session_id: approval.session_id,
    request_fingerprint: approval.fingerprint,
    requested_action: approval.requested_action ?? approval.request,
    ...(plan ? { remediation_id: plan.id, original_config: plan.original_config, proposed_config: plan.proposed_config, reason: plan.reason } : {}),
  };
}

function Badge({ children, tone = 'neutral', dot = false }: { children: ReactNode; tone?: string; dot?: boolean }) {
  return <span className={`badge ${tone}`}>{dot && <span className="status-dot" />}{children}</span>;
}
function EmptyState({ icon: Icon = ShieldCheck, title, text }: { icon?: typeof ShieldCheck; title: string; text: string }) {
  return <div className="empty-state"><div className="empty-icon"><Icon size={21} /></div><strong>{title}</strong><p>{text}</p></div>;
}

export default function App() {
  const [view, setView] = useState<View>('command');
  const [token, setToken] = useState('');
  const [role, setRole] = useState<'admin' | 'analyst'>('admin');
  const [credential, setCredential] = useState('');
  const [state, setState] = useState<State>(EMPTY);
  const [connected, setConnected] = useState(false);
  const [connectOpen, setConnectOpen] = useState(false);
  const [connectError, setConnectError] = useState('');
  const [busy, setBusy] = useState('');
  const [toast, setToast] = useState<{ text: string; error?: boolean } | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [query, setQuery] = useState('');
  const [eventFilter, setEventFilter] = useState('all');
  const [selected, setSelected] = useState<Event | null>(null);
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [reviewNote, setReviewNote] = useState('');
  const [mobileOpen, setMobileOpen] = useState(false);
  const [demoResult, setDemoResult] = useState<DemoResult | null>(null);
  const [newAgentOpen, setNewAgentOpen] = useState(false);
  const [newAgentName, setNewAgentName] = useState('');
  const [newAgentToken, setNewAgentToken] = useState('');

  const api = useCallback(async (path: string, init?: RequestInit, bearer?: string) => {
    const response = await fetch(path, {
      ...init,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer ?? token}`, ...init?.headers },
    });
    const result = await response.json().catch(() => ({ detail: `Request returned HTTP ${response.status}` }));
    if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : `Request rejected (HTTP ${response.status})`);
    return result;
  }, [token]);

  const reload = useCallback(async (bearer?: string) => {
    const result = await api('/api/state', undefined, bearer);
    setState(normalizeState(result));
    setLastUpdate(new Date());
  }, [api]);

  useEffect(() => {
    if (!connected || role !== 'admin') return;
    const interval = window.setInterval(() => {
      reload().catch(error => setToast({ text: `Console update failed: ${error.message}`, error: true }));
    }, 3000);
    return () => window.clearInterval(interval);
  }, [connected, reload, role]);
  useEffect(() => { if (!toast) return; const timer = window.setTimeout(() => setToast(null), 6500); return () => window.clearTimeout(timer); }, [toast]);
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !busy) { setConnectOpen(false); setSelected(null); setConfirmation(null); setDemoResult(null); setNewAgentOpen(false); setNewAgentToken(''); }
    };
    window.addEventListener('keydown', handler); return () => window.removeEventListener('keydown', handler);
  }, [busy]);

  const runAction = async (key: string, action: () => Promise<void>) => {
    if (busy) return;
    setBusy(key);
    try { await action(); } catch (error) { setToast({ text: error instanceof Error ? error.message : 'The operation could not be completed.', error: true }); }
    finally { setBusy(''); }
  };
  const connect = async (event: FormEvent) => {
    event.preventDefault(); setConnectError(''); setBusy('connect');
    try {
      const authenticated = await api('/api/auth/role', undefined, credential.trim());
      if (!['admin', 'analyst'].includes(authenticated.role)) throw new Error('The server did not return an authorized security role.');
      const nextRole: 'admin' | 'analyst' = authenticated.role;
      if (nextRole === 'admin') await reload(credential.trim());
      else { setState(EMPTY); setLastUpdate(new Date()); setView('command'); }
      setRole(nextRole); setToken(credential.trim()); setCredential(''); setConnected(true); setConnectOpen(false);
      setToast({ text: 'Security console connected. Your authenticated role controls available actions.' });
    } catch (error) { setConnectError(error instanceof Error ? error.message : 'Connection failed'); }
    finally { setBusy(''); }
  };
  const needConnection = () => { if (connected) return true; setConnectOpen(true); return false; };
  const confirm = (item: Confirmation) => { if (!needConnection()) return; setReviewNote(''); setConfirmation(item); };
  const submitConfirmation = async (event: FormEvent) => {
    event.preventDefault(); if (!confirmation) return;
    await runAction('confirm', async () => { await confirmation.action(reviewNote); await reload(); setConfirmation(null); setToast({ text: 'Action recorded in the security audit trail.' }); });
  };
  const runDemo = (scenario: string) => {
    if (!needConnection()) return;
    void runAction(`demo-${scenario}`, async () => {
      const result = await api(`/api/demo/run/${scenario}`, { method: 'POST', body: '{}' });
      setDemoResult(result); await reload();
      setToast({ text: scenario === 'c' ? 'Least-privilege proposal created. Human approval is required.' : 'Simulation complete. Inspect the intercepted actions below.' });
    });
  };
  const reviewApproval = (approval: Approval, approved: boolean) => confirm({
    title: approved ? 'Approve this scoped request?' : 'Reject this request?',
    description: approved ? 'This approval applies only to the recorded request or synthetic remediation. Mandatory security policy still applies.' : 'The operation will remain blocked. The decision is recorded with your authority identity.',
    actionLabel: approved ? 'Approve request' : 'Reject request', danger: !approved,
    evidence: approvalEvidence(approval, state.remediations),
    action: async note => { await api(`/api/approvals/${approval.id}/review`, { method: 'POST', body: JSON.stringify({ approved, reviewer: 'local-security-authority', note }) }); },
  });
  const applyRemediation = (item: Remediation) => confirm({
    title: 'Apply the approved remediation?', description: 'SENTINEL will update the synthetic agent configuration, preserve the original, and validate the narrower permissions. Quarantined sessions require a separate restoration review.', actionLabel: 'Apply & validate',
    evidence: { original_config: item.original_config, proposed_config: item.proposed_config },
    action: async () => { await api(`/api/remediations/${item.id}/apply`, { method: 'POST', body: JSON.stringify({ reviewer: 'local-security-authority' }) }); },
  });
  const rollback = (item: Remediation) => confirm({
    title: 'Roll back this synthetic configuration?', description: 'The stored original permission configuration will be restored. This can reintroduce excessive permissions. Quarantine and mandatory gateway policies remain enforced.', actionLabel: 'Authorize rollback', danger: true, requireNote: false,
    action: async () => { await api(`/api/remediations/${item.id}/rollback`, { method: 'POST', body: JSON.stringify({ reviewer: 'local-security-authority' }) }); },
  });
  const restore = (agent: Session) => confirm({
    title: 'Review session restoration', description: 'Confirm that the compromise has been investigated and recovery validation has passed. Restoration does not grant additional capabilities.', actionLabel: 'Validate & restore', requireNote: true,
    action: async note => { await api(`/api/sessions/${agent.id}/restore`, { method: 'POST', body: JSON.stringify({ reviewer: 'local-security-authority', note }) }); },
  });
  const propose = (agent: Session) => {
    if (!needConnection()) return;
    void runAction(`propose-${agent.id}`, async () => { await api('/api/remediations', { method: 'POST', body: JSON.stringify({ session_id: agent.id }) }); await reload(); setView('approvals'); setToast({ text: 'Remediation proposed. Review and approve before applying.' }); });
  };
  const reviewIncident = (item: Event) => confirm({
    title: 'Record an incident review', description: 'Document your investigation or false-positive appeal. A review adds evidence to the incident lifecycle; it does not override mandatory policy.', actionLabel: 'Record review', requireNote: true,
    action: async note => { await api(`/api/incidents/${item.id}/review`, { method: 'POST', body: JSON.stringify({ reviewer: 'local-security-authority', note }) }); setSelected(null); },
  });
  const verifyAudit = () => {
    if (!needConnection()) return;
    void runAction('audit', async () => { const result = await api('/api/audit/verify'); setToast({ text: result.valid ? `Audit integrity verified · ${result.count ?? state.events.length} records checked` : 'Audit verification failed. Gateway execution is suspended.', error: !result.valid }); await reload(); });
  };
  const createAgent = async (event: FormEvent) => {
    event.preventDefault();
    await runAction('create-agent', async () => {
      const result = await api('/api/sessions', { method: 'POST', body: JSON.stringify({ agent_id: newAgentName.trim(), role: 'developer', capabilities: ['files:read', 'files:write', 'delegate'], ttl_seconds: 3600 }) });
      setNewAgentToken(result.token || result.session_token || ''); await reload();
    });
  };
  const exportEvents = () => {
    if (!needConnection()) return;
    const url = URL.createObjectURL(new Blob([formatJson({ exported_at: new Date().toISOString(), events: state.events, incidents: state.incidents })], { type: 'application/json' }));
    const a = document.createElement('a'); a.href = url; a.download = `sentinel-events-${new Date().toISOString().slice(0, 10)}.json`; a.click(); URL.revokeObjectURL(url);
  };

  const activeAgents = state.agents.filter(a => a.status === 'active');
  const activeCount = Number(state.metrics.active_agents ?? activeAgents.length);
  const quarantined = state.agents.filter(a => /quarant|suspend/.test(a.status));
  const pending = state.approvals.filter(pendingApproval);
  const blocked = state.events.filter(e => ['deny', 'quarantine'].includes(e.decision));
  const allowed = state.events.filter(e => e.executed);
  const latencies = state.events.map(e => Number(e.latency_ms)).filter(Number.isFinite).sort((a, b) => a - b);
  const measuredMedian = Number(state.metrics.median_policy_latency_ms);
  const fallbackMedian = latencies.length ? (latencies[Math.floor((latencies.length - 1) / 2)] + latencies[Math.floor(latencies.length / 2)]) / 2 : null;
  const medianLatency = state.events.length ? (Number.isFinite(measuredMedian) ? measuredMedian : fallbackMedian)?.toFixed(1) : null;
  const riskDistribution = riskLabels.map((_, level) => state.events.filter(e => e.risk_level === level).length);
  const filteredEvents = useMemo(() => {
    const source = view === 'incidents' ? state.incidents : state.events;
    return source.filter(e => (eventFilter === 'all' || (eventFilter === 'blocked' ? ['deny', 'quarantine'].includes(e.decision) : eventFilter === 'allowed' ? e.executed : e.decision === 'approval')) && `${e.agent_id} ${e.explanation} ${e.requested_action?.tool} ${e.requested_action?.operation} ${e.id}`.toLowerCase().includes(query.toLowerCase()));
  }, [state.events, state.incidents, eventFilter, query, view]);
  const viewTitle = nav.find(item => item.id === view)?.label || 'Overview';
  const openView = (next: View) => { if (connected && role === 'analyst' && !['command', 'accountwatch'].includes(next)) return; setView(next); setQuery(''); setEventFilter('all'); setMobileOpen(false); };

  const eventTable = (events: Event[], compact = false) => <div className="table-scroll"><table className="event-table"><thead><tr><th>Event / agent</th><th>Action</th><th>Risk level</th><th>Decision</th><th>Time</th><th className="table-arrow" /></tr></thead><tbody>
    {events.map(event => <tr key={event.id} onClick={() => setSelected(event)} tabIndex={0} onKeyDown={e => { if (e.key === 'Enter') setSelected(event); }} aria-label={`Inspect event ${event.id}`}>
      <td><div className="event-identity"><span className={`event-icon risk-${event.risk_level}`}>{event.risk_level >= 3 ? <ShieldAlert size={16} /> : event.executed ? <Check size={16} /> : <Clock3 size={16} />}</span><div><strong>{event.agent_id || 'Unknown agent'}</strong><span className="mono">{shortId(event.id)}{compact ? '' : ` · ${human(event.event_type)}`}</span></div></div></td>
      <td><span className="action-label mono">{String(event.requested_action?.tool || 'gateway')}<span className="muted">.</span>{String(event.requested_action?.operation || 'evaluate')}</span><span className="resource-label">{String(event.requested_action?.resource || event.requested_action?.destination || 'Policy evaluation')}</span></td>
      <td><span className={`risk-label risk-${event.risk_level}`}><i />L{event.risk_level} <span>{riskLabels[event.risk_level] || 'Unknown'}</span></span></td>
      <td><Badge tone={['deny', 'quarantine'].includes(event.decision) ? 'red' : event.decision === 'approval' ? 'amber' : 'green'}>{titleCase(event.decision)}</Badge></td>
      <td className="mono time-cell">{fmtTime(event.timestamp)}</td><td className="table-arrow"><ArrowUpRight size={15} /></td>
    </tr>)}
  </tbody></table>{!events.length && <EmptyState icon={Activity} title={connected ? 'No matching events' : 'Your activity will appear here'} text={connected ? 'Run a controlled simulation or send a request through the protected gateway.' : 'Connect the local security authority to inspect real gateway decisions.'} />}</div>;

  const hasRecoveryPlan = (sessionId: string) => state.remediations.some(item => item.session_id === sessionId && statusOf(item) === 'validated' && (item.validation as { passed?: boolean } | null)?.passed === true);

  const agentCards = (compact = false) => <div className={`agent-grid ${compact ? 'compact' : ''}`}>
    {(compact ? state.agents.slice(0, 4) : state.agents).map(agent => <div className="agent-card" key={agent.id}>
      <div className="agent-card-top"><span className={`avatar ${/quarant|suspend/.test(agent.status) ? 'quarantined' : ''}`}><Bot size={20} /></span><Badge dot tone={agent.status === 'active' ? 'green' : /quarant|suspend/.test(agent.status) ? 'red' : 'neutral'}>{titleCase(agent.status)}</Badge></div>
      <h3>{agent.agent_id}</h3><div className="agent-meta mono">{shortId(agent.id)}<span> / </span>{agent.role || 'developer'}</div>
      <div className="capabilities">{(agent.capabilities || []).slice(0, compact ? 3 : 8).map(cap => <code key={cap}>{cap}</code>)}{compact && agent.capabilities?.length > 3 && <code>+{agent.capabilities.length - 3}</code>}</div>
      <div className="agent-card-bottom"><span>{agent.parent_session_id ? <><GitBranch size={12} /> Delegated · {shortId(agent.parent_session_id)}</> : <><Fingerprint size={12} /> Scoped session</>}</span>
      {!compact && <div className="agent-actions">{/quarant|suspend/.test(agent.status) ? <button className="text-button" disabled={!!busy} onClick={() => hasRecoveryPlan(agent.id) ? restore(agent) : propose(agent)}>{hasRecoveryPlan(agent.id) ? 'Review recovery' : 'Propose recovery'} <ArrowRight size={12} /></button> : <button className="text-button" disabled={!!busy} onClick={() => propose(agent)}>Review scope <SlidersHorizontal size={12} /></button>}</div>}</div>
    </div>)}
    {!state.agents.length && <div className="agent-empty"><Bot size={28} /><h3>No protected sessions yet</h3><p>Create a scoped agent or run a simulation to establish the first trust boundary.</p><button className="button secondary small" onClick={() => { if (needConnection()) setNewAgentOpen(true); }}><Plus size={14} /> Create agent session</button></div>}
  </div>;

  return <div className="app-shell">
    {mobileOpen && <button className="sidebar-overlay" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}
    <aside className={`sidebar ${mobileOpen ? 'mobile-open' : ''}`}>
      <a href="#" className="brand" onClick={e => { e.preventDefault(); openView('command'); }} aria-label="SENTINEL Command"><span className="brand-mark"><ShieldCheck size={23} strokeWidth={1.8} /></span><span>SENTINEL<span className="brand-subtitle">ENTERPRISE SECURITY PROTOTYPE</span></span></a>
      <div className="workspace-switch"><div className="workspace-icon"><TerminalSquare size={17} /></div><div><strong>Enterprise workspace</strong><span>Synthetic / Cisco-oriented concept</span></div><ChevronDown size={14} className="muted" /></div>
      <div className="nav-heading">WORKSPACE</div>
      <nav aria-label="Primary navigation">{nav.map(item => <button key={item.id} className={`nav-item ${view === item.id ? 'active' : ''}`} onClick={() => openView(item.id)} disabled={connected && role === 'analyst' && !['command', 'accountwatch'].includes(item.id)} title={connected && role === 'analyst' && !['command', 'accountwatch'].includes(item.id) ? 'Administrator authority required' : item.label}><item.icon size={18} /><span>{item.label}</span>{item.id === 'approvals' && pending.length > 0 && <span className="nav-count">{pending.length}</span>}{item.id === 'incidents' && state.incidents.length > 0 && <span className="nav-count neutral-count">{state.incidents.length}</span>}</button>)}</nav>
      <div className="sidebar-bottom"><div className="boundary-card"><div className="boundary-title"><LockKeyhole size={15} /><span>Enforced at the gateway</span></div><p>Explicit scopes. Independent policy. Human oversight.</p><button onClick={() => openView('policy')}>View enforcement boundary <ArrowUpRight size={13} /></button></div>
        <button className="authority-profile" onClick={() => { if (connected) { setToken(''); setConnected(false); setState(EMPTY); setLastUpdate(null); setSelected(null); setConfirmation(null); setDemoResult(null); setNewAgentToken(''); setNewAgentOpen(false); setToast({ text: 'Authority disconnected. Browser credentials cleared.' }); } else setConnectOpen(true); }}><span className="profile-avatar"><UserRound size={17} /></span><span><strong>{connected ? role === 'analyst' ? 'Security analyst' : 'Security authority' : 'Local observer'}</strong><small>{connected ? 'Disconnect authority' : 'Connect authority'}</small></span><span className={`profile-indicator ${connected ? 'online' : ''}`} /></button>
      </div>
    </aside>

    <div className="main-shell">
      <header className="topbar"><div className="breadcrumb"><button className="icon-button mobile-menu" aria-label="Open navigation" onClick={() => setMobileOpen(true)}><Menu size={20} /></button><span>Workspace</span><ChevronRight size={13} /><strong>{viewTitle}</strong></div><div className="topbar-right"><span className="local-label"><span className="status-dot" />LOCAL SANDBOX</span><span className="topbar-divider" /><button className="icon-button" title="Open pending approvals" aria-label="Open pending approvals" onClick={() => openView('approvals')}><Bell size={17} />{pending.length > 0 && <span className="notification-dot" />}</button><span className="topbar-avatar">SA</span></div></header>

      <main>
        <div className="page-heading"><div><div className="eyebrow"><span />SECURITY OPERATIONS</div><h1>{view === 'command' ? 'A clear view. A shared defense.' : view === 'accountwatch' ? 'See behavior. Understand risk.' : view === 'overview' ? 'AgentGuard. Policy before action.' : viewTitle}</h1><p>{view === 'command' ? 'Explainable security across employee identities and autonomous agents.' : view === 'accountwatch' ? 'Metadata-only behavioral analytics. An anomaly is a reason to review, not a conclusion.' : view === 'overview' ? 'Inspect gateway actions. Keep your team in control.' : view === 'activity' ? 'Every intercepted operation, with a decision you can explain.' : view === 'agents' ? 'Scoped identities and explicit capabilities for every protected session.' : view === 'approvals' ? 'Human judgment for impactful changes and controlled recovery.' : view === 'incidents' ? 'Review evidence, document appeals, and coordinate safe recovery.' : 'Understand the rules and the precise limits of this local MVP.'}</p></div>{!['command', 'accountwatch'].includes(view) && <div className="heading-actions"><button className="button secondary" onClick={exportEvents}><ArrowDownToLine size={15} />Export events</button><button className="button primary" onClick={() => runDemo('all')} disabled={!!busy}>{busy.startsWith('demo') ? <LoaderCircle className="spin" size={15} /> : <Play size={14} fill="currentColor" />}{busy.startsWith('demo') ? 'Running simulation' : 'Run simulation'}</button></div>}</div>

        <div className={`system-strip ${connected && state.health.audit_valid === false ? 'system-warning' : ''}`}><div className="system-status"><span className={`pulse-dot ${connected ? '' : 'offline'}`} /><strong>{connected ? state.health.audit_valid === false ? 'Audit integrity requires attention' : role === 'analyst' ? 'Analyst console connected' : 'Security services connected' : 'Local console ready'}</strong><span className="strip-separator" /><span>{connected ? 'Synthetic events · independent policy · human-supervised response' : 'Connect your authority to inspect live security decisions'}</span></div><div className="system-strip-end">{connected ? <><span className="live-indicator">LIVE</span><span>Updated {lastUpdate?.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false })}</span><button className="icon-button" aria-label="Refresh security state" disabled={!!busy} onClick={() => void runAction('refresh', reload)}><RefreshCw size={13} className={busy === 'refresh' ? 'spin' : ''} /></button></> : <button onClick={() => setConnectOpen(true)}>Connect authority <ArrowRight size={13} /></button>}</div></div>

        {(view === 'command' || view === 'accountwatch') && <EnterpriseConsole key={connected ? role : 'observer'} view={view} api={api} connected={connected} role={role} onConnect={() => setConnectOpen(true)} onNavigate={next => openView(next)} />}

        {view === 'overview' && <>
          <div className="metrics-grid">
            <Metric title="Protected agents" value={connected ? String(activeCount) : '—'} icon={<Bot size={18} />} detail={connected ? `${state.agents.length} total sessions · ${quarantined.length} quarantined` : 'Scoped identities, explicit permissions'} tag="IDENTITY" />
            <Metric title="Actions intercepted" value={connected ? state.events.length.toLocaleString() : '—'} icon={<Workflow size={18} />} detail={connected ? `${allowed.length} executed within policy` : 'Independent checks before execution'} tag="ENFORCEMENT" />
            <Metric title="Threats blocked" value={connected ? String(blocked.length) : '—'} icon={<ShieldAlert size={18} />} detail={connected ? `${state.incidents.filter(e => e.risk_level === 4).length} critical incidents recorded` : 'Mandatory constraints stay enforced'} tag="PROTECTION" accent="rose" />
            <Metric title="Pending approvals" value={connected ? String(pending.length) : '—'} icon={<FileCheck2 size={18} />} detail={connected ? 'Impactful changes require your review' : 'Human oversight at every escalation'} tag="HUMAN OVERSIGHT" accent="amber" />
          </div>

          <div className="overview-middle">
            <section className="panel risk-panel"><PanelHeading icon={<Activity size={17} />} title="Risk distribution" right={<span className="panel-caption">CURRENT AUDIT WINDOW</span>} /><div className="risk-body"><div className="risk-stat"><span className="risk-total">{connected ? state.events.length : '—'}</span><span>evaluated actions</span><div className="risk-sub"><ShieldCheck size={13} />{connected ? `${blocked.length} threats contained before execution` : 'Explainable, deterministic decisions'}</div></div><div className="bar-chart" role="img" aria-label={`Risk distribution: ${riskDistribution.map((n, i) => `${riskLabels[i]} ${n}`).join(', ')}`}>
              {riskDistribution.map((count, i) => <div className="bar-column" key={i}><span className="bar-value">{connected ? count : '—'}</span><div className="bar-track"><div className={`risk-bar level-${i}`} style={{ height: connected && state.events.length ? `${Math.max(count > 0 ? 5 : 0, (count / Math.max(...riskDistribution, 1)) * 100)}%` : '2px', backgroundColor: riskColors[i] }} /></div><span className="bar-label">L{i}</span></div>)}
            </div></div><div className="risk-legend">{riskLabels.map((label, i) => <span key={label}><i style={{ background: riskColors[i] }} />{label}</span>)}</div></section>
            <section className="panel posture-panel"><PanelHeading icon={<ShieldCheck size={17} />} title="Enforcement posture" right={<Badge tone={connected ? state.health.audit_valid === false ? 'red' : 'green' : 'neutral'} dot>{connected ? state.health.audit_valid === false ? 'Attention' : 'Active' : 'Not connected'}</Badge>} /><div className="posture-list"><PostureRow label="Deterministic policy engine" text="Mandatory rules evaluated independently" icon={<SlidersHorizontal size={16} />} status={connected ? 'Enforced' : 'Ready'} /><PostureRow label="Tamper-evident audit trail" text="Sanitized records with integrity verification" icon={<Fingerprint size={16} />} status={connected ? state.health.audit_valid === false ? 'Invalid' : 'Verified' : 'Awaiting data'} /><PostureRow label="Human-supervised recovery" text="Approve, apply, validate, then restore" icon={<UserRound size={16} />} status="Required" /></div><div className="posture-footer"><span><Clock3 size={13} />Median policy evaluation</span><strong>{medianLatency ? `${medianLatency} ms` : 'No measurements yet'}</strong></div></section>
          </div>

          <section className="panel activity-panel"><PanelHeading icon={<Activity size={17} />} title="Recent intercepted actions" right={<button className="text-button" onClick={() => openView('activity')}>View all activity <ArrowRight size={14} /></button>} />{eventTable(state.events.slice(0, 5), true)}</section>

          <div className="section-heading"><div><h2>Test the trust boundary<span className="small-tag">CONTROLLED SIMULATIONS</span></h2><p>Five synthetic scenarios. Real gateway decisions. No live credentials.</p></div><button className="text-button" onClick={() => openView('policy')}>How protection works <ArrowUpRight size={14} /></button></div>
          <div className="scenario-grid">{scenarios.map(scenario => <button key={scenario.id} className="scenario-card" disabled={!!busy} onClick={() => runDemo(scenario.id)}><div className="scenario-top"><span className={`scenario-icon ${scenario.color}`}><scenario.icon size={19} /></span><span className="scenario-letter">0{scenario.id.charCodeAt(0) - 96}</span></div><span className="scenario-category">{scenario.label}</span><h3>{scenario.name}</h3><p>{scenario.description}</p><span className="scenario-cta">Run scenario {scenario.id.toUpperCase()}<ArrowRight size={14} /></span></button>)}</div>

          <div className="section-heading agents-heading"><div><h2>Protected agents<span className="count-label">{state.agents.length}</span></h2><p>Every session has its own identity, scope, and trust status.</p></div><button className="text-button" onClick={() => openView('agents')}>Manage agents <ArrowRight size={14} /></button></div>{agentCards(true)}
        </>}

        {(view === 'activity' || view === 'incidents') && <section className="panel all-events-panel"><div className="table-toolbar"><div className="filter-tabs">{['all', 'blocked', 'allowed', 'approval'].map(filter => <button key={filter} className={eventFilter === filter ? 'selected' : ''} onClick={() => setEventFilter(filter)}>{filter === 'all' ? 'All events' : filter === 'approval' ? 'Needs approval' : titleCase(filter)}</button>)}</div><label className="search-input"><Search size={15} /><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search agent, action, or event…" aria-label="Search security events" /></label></div><div className="results-label"><ListFilter size={13} />{filteredEvents.length} {view === 'incidents' ? 'incidents' : 'events'}<span>Times shown in your local timezone</span></div>{eventTable(filteredEvents)}<div className="table-footer"><span>Sanitized evidence · secrets and unnecessary personal data redacted</span><button className="text-button" onClick={verifyAudit} disabled={!!busy}><Fingerprint size={13} />Verify audit integrity</button></div></section>}

        {view === 'agents' && <><div className="inline-notice"><Fingerprint size={18} /><p><strong>Capabilities are explicit.</strong> A parent cannot delegate capabilities it does not hold. Session quarantine propagates through ancestry checks.</p><button className="button secondary small" onClick={() => { if (needConnection()) { setNewAgentName(''); setNewAgentToken(''); setNewAgentOpen(true); } }}><Plus size={14} />New session</button></div>{agentCards()}<div className="scope-note"><LockKeyhole size={15} /><span>Only actions routed through the gateway are protected. Direct host tools remain outside this enforcement boundary.</span></div></>}

        {view === 'approvals' && <><div className="inline-notice"><UserRound size={18} /><p><strong>Your authority stays separate.</strong> Protected agents cannot approve their own requests or authorize restoration. Review each change before applying it.</p></div><div className="approval-layout"><section className="panel"><PanelHeading icon={<FileCheck2 size={17} />} title="Approval queue" right={<span className="count-label">{pending.length} pending</span>} /><div className="approval-list">{state.approvals.map(approval => <div className="approval-card" key={approval.id}><div className="approval-card-heading"><span className="approval-icon"><FileCheck2 size={18} /></span><div><h3>{approval.remediation_id || approval.kind?.includes('remediat') || approval.type?.includes('remediat') ? 'Agent configuration remediation' : 'Scoped operation approval'}</h3><span className="mono">{shortId(approval.id)} · session {shortId(approval.session_id)}</span></div><Badge tone={pendingApproval(approval) ? 'amber' : statusOf(approval) === 'approved' ? 'green' : 'neutral'}>{titleCase(approval.status)}</Badge></div><p>Bound to the recorded session and request. Approval cannot bypass a mandatory security constraint.</p><EvidencePreview title="Review the exact request" value={approvalEvidence(approval, state.remediations)} expanded={pendingApproval(approval)} />{approval.expires_at && <div className="approval-expiry"><Clock3 size={12} />Expires {fmtDate(approval.expires_at)}</div>}{pendingApproval(approval) && <div className="approval-buttons"><button className="button secondary small" onClick={() => reviewApproval(approval, false)} disabled={!!busy}><X size={13} />Reject</button><button className="button primary small" onClick={() => reviewApproval(approval, true)} disabled={!!busy}><Check size={13} />Approve request</button></div>}</div>)}{!state.approvals.length && <EmptyState icon={CheckCheck} title="No approvals waiting" text="Run the excessive-permissions scenario to propose a synthetic configuration change." />}</div></section><section className="panel"><PanelHeading icon={<Workflow size={17} />} title="Remediation workflow" right={<span className="panel-caption">SANDBOX ONLY</span>} /><div className="remediation-list">{state.remediations.map(item => { const status = statusOf(item); const approval = state.approvals.find(a => a.id === item.approval_id || a.remediation_id === item.id); return <div className="remediation-card" key={item.id}><div className="remediation-heading"><strong>Least-privilege configuration</strong><Badge tone={/validat|applied|restored/.test(status) ? 'green' : /rolled.?back|rollback/.test(status) ? 'neutral' : 'amber'}>{titleCase(status)}</Badge></div><span className="mono muted">{shortId(item.id)} · {shortId(item.session_id)}</span><div className="workflow-steps">{['Propose', 'Approve', 'Apply', 'Validate'].map((label, i) => <span key={label} className={i === 0 || (i === 1 && (status !== 'proposed' || approval?.status === 'approved')) || (i >= 2 && /applied|validat|restored|rolled.?back|rollback/.test(status)) ? 'done' : ''}><Check size={10} />{label}</span>)}</div><div className="config-diff"><div><span>ORIGINAL SCOPE</span><code>{(item.original_capabilities || (item.original_config as { capabilities?: string[] })?.capabilities || ['Stored with proposal']).join(', ')}</code></div><ArrowDownToLine size={13} /><div><span>PROPOSED SCOPE</span><code>{(item.proposed_capabilities || item.recommended_capabilities || (item.proposed_config as { capabilities?: string[] })?.capabilities || ['Least-privilege configuration']).join(', ')}</code></div></div>{item.validation != null && <EvidencePreview title={(item.validation as { passed?: boolean }).passed === false ? "Inspect failed validation checks" : "Inspect recovery validation"} value={item.validation} />}<div className="remediation-actions">{!/applied|validat|restored|rolled.?back|rollback/.test(status) && <button className="button primary small" disabled={!!busy || (approval ? statusOf(approval) !== 'approved' : status !== 'approved')} onClick={() => applyRemediation(item)}>Apply & validate <ArrowRight size={13} /></button>}{/applied|validat|restored/.test(status) && <button className="button secondary small" disabled={!!busy} onClick={() => rollback(item)}>Authorize rollback</button>}</div></div>; })}{!state.remediations.length && <EmptyState icon={Workflow} title="Safe recovery starts with a proposal" text="SENTINEL preserves the original configuration, requests approval, and validates each applied change." />}</div></section></div></>}

        {view === 'policy' && <div className="policy-layout"><section className="panel"><PanelHeading icon={<ShieldCheck size={17} />} title="An independent enforcement boundary" right={<Badge tone="green">LOCAL MVP</Badge>} /><div className="policy-content"><p className="policy-lede">Instructions can guide an agent. Only the gateway can authorize a protected tool action.</p><div className="boundary-diagram"><div><Bot size={20} /><strong>Protected agent</strong><span>Scoped token</span></div><ArrowRight size={20} /><div className="gateway-node"><ShieldCheck size={23} /><strong>SENTINEL gateway</strong><span>Authenticate → evaluate → record</span></div><ArrowRight size={20} /><div><Code2 size={20} /><strong>Fixed adapters</strong><span>Sandbox files · mock outbox</span></div></div><div className="policy-points"><div><CheckCircle2 size={17} /><p><strong>Protected through this gateway</strong><span>Scoped sandbox file actions, local mock outbound requests, delegated sessions, approvals, and synthetic remediation.</span></p></div><div><TriangleAlert size={17} /><p><strong>Outside the MVP boundary</strong><span>Direct IDE tools, arbitrary host commands, third-party extensions, and network or filesystem access that bypasses the gateway.</span></p></div><div><Fingerprint size={17} /><p><strong>Local audit integrity</strong><span>Hash-chained, sanitized events expose modification. The local host and gateway process remain trusted components.</span></p></div></div><div className="policy-actions"><button className="button secondary" onClick={verifyAudit} disabled={!!busy}><Fingerprint size={14} />Verify audit chain</button><Badge tone={connected ? state.health.audit_valid === false ? 'red' : 'green' : 'neutral'}>{connected ? state.health.audit_valid === false ? 'Integrity failed' : 'Integrity verified' : 'Connect to verify'}</Badge></div></div></section><section className="panel"><PanelHeading icon={<SlidersHorizontal size={17} />} title="Risk & response policy" /><div className="risk-policy-list">{riskLabels.map((label, level) => <div key={label}><span className={`risk-level-box risk-${level}`}>L{level}</span><div><strong>{label}</strong><span>{['Allow authorized actions and record relevant metadata.', 'Allow with monitoring and contextual guidance.', 'Pause the operation for scoped human approval.', 'Deny the operation, preserve evidence, and alert.', 'Block and quarantine the session; require authorized recovery.'][level]}</span></div><Badge tone={level < 2 ? 'green' : level === 2 ? 'amber' : 'red'}>{['Allow', 'Monitor', 'Approval', 'Deny', 'Quarantine'][level]}</Badge></div>)}</div></section><section className="panel"><PanelHeading icon={<TerminalSquare size={17} />} title="Connect an agent runtime" /><div className="policy-content"><p>Use the sample MCP integration to route supported tools through the authenticated gateway. Supply a short-lived agent token through the process environment.</p><pre className="code-block"><code>{'SENTINEL_URL=http://127.0.0.1:8000\nSENTINEL_AGENT_TOKEN=<scoped-session-token>\npython -m sentinel.mcp_server'}</code></pre><p className="small-print">MCP is an integration mechanism. It does not intercept unrelated IDE actions. Read the repository’s integration instructions before enabling tools.</p></div></section><section className="panel"><PanelHeading icon={<Settings2 size={17} />} title="Organizational configuration" right={<Badge>READ ONLY</Badge>} /><div className="policy-content">{connected ? <pre className="code-block policy-json"><code>{formatJson(state.policy)}</code></pre> : <EmptyState icon={SlidersHorizontal} title="Policy loaded by the local gateway" text="Connect the local authority to inspect the active organization policy." />}</div></section></div>}

        <footer className="page-footer"><div><Shield size={13} /><span>SENTINEL <span className="muted">/</span> Local security orchestration</span></div><span>Synthetic data only<span className="footer-dot">·</span>Human authority by design<span className="footer-dot">·</span>Enterprise prototype</span></footer>
      </main>
    </div>

    {toast && <div className={`toast ${toast.error ? 'error' : ''}`} role="status">{toast.error ? <TriangleAlert size={17} /> : <CheckCircle2 size={17} />}<span>{toast.text}</span><button className="icon-button" onClick={() => setToast(null)} aria-label="Dismiss notification"><X size={15} /></button></div>}

    {connectOpen && <Modal title="Connect local authority" subtitle="Organizational security access" onClose={() => { if (!busy) { setConnectOpen(false); setCredential(''); setConnectError(''); } }}><form onSubmit={connect}><div className="connect-intro"><span className="modal-shield"><ShieldCheck size={26} /></span><p>Enter an administrator or analyst credential. Analyst access includes behavioral investigation; privileged changes require administrator authority.</p></div><label className="form-label" htmlFor="authority-token">Security console token</label><input id="authority-token" type="password" className="text-input" placeholder="Paste your local admin token" value={credential} onChange={e => setCredential(e.target.value)} autoFocus autoComplete="off" required /><div className="token-help"><TerminalSquare size={15} /><div><strong>Get the token from your local server</strong><code>cat .sentinel-data/admin.token</code><p>Keep this token private. It authorizes security administration.</p></div></div>{connectError && <div className="form-error" role="alert"><TriangleAlert size={14} />{connectError}</div>}<div className="modal-footer"><span><LockKeyhole size={12} />Held in browser memory only</span><button className="button primary" disabled={!!busy || !credential.trim()}>{busy === 'connect' ? <LoaderCircle className="spin" size={14} /> : <ArrowRight size={14} />}Connect authority</button></div></form></Modal>}

    {confirmation && <Modal title={confirmation.title} subtitle="Human authorization required" onClose={() => { if (!busy) setConfirmation(null); }}><form onSubmit={submitConfirmation}><p className="modal-description">{confirmation.description}</p>{confirmation.evidence != null && <EvidencePreview title="Review the exact authorized change" value={confirmation.evidence} expanded />}{confirmation.requireNote && <><label className="form-label" htmlFor="review-note">Review note</label><textarea id="review-note" className="text-input" placeholder="Document your investigation and validation evidence…" value={reviewNote} onChange={e => setReviewNote(e.target.value)} minLength={5} required autoFocus rows={4} /></>}<div className="modal-footer"><button type="button" className="button secondary" disabled={!!busy} onClick={() => setConfirmation(null)}>Cancel</button><button className={`button ${confirmation.danger ? 'danger' : 'primary'}`} disabled={!!busy || (confirmation.requireNote && reviewNote.trim().length < 5)}>{busy === 'confirm' && <LoaderCircle className="spin" size={14} />}{confirmation.actionLabel}</button></div></form></Modal>}

    {newAgentOpen && <Modal title={newAgentToken ? 'Session token issued' : 'Create a protected agent'} subtitle="Scoped, short-lived identity" onClose={() => { if (!busy) { setNewAgentOpen(false); setNewAgentToken(''); } }}><form onSubmit={createAgent}>{newAgentToken ? <><p className="modal-description">Copy this token into the protected runtime’s environment. It is shown only on issuance and is never included in the event stream.</p><div className="issued-token"><code>{newAgentToken}</code><button type="button" className="icon-button" aria-label="Copy agent token" onClick={() => navigator.clipboard.writeText(newAgentToken).then(() => setToast({ text: 'Scoped token copied.' })).catch(() => setToast({ text: 'Clipboard unavailable. Select and copy the token manually.', error: true }))}><Copy size={15} /></button></div><div className="modal-footer"><span>Expires in one hour</span><button type="button" className="button primary" onClick={() => { setNewAgentOpen(false); setNewAgentToken(''); }}>Done</button></div></> : <><label className="form-label" htmlFor="agent-name">Agent identity</label><input id="agent-name" className="text-input" value={newAgentName} onChange={e => setNewAgentName(e.target.value)} placeholder="e.g. frontend-developer" required maxLength={80} autoFocus /><div className="creation-scope"><span className="form-label">Initial capabilities</span><div className="capabilities"><code>files:read</code><code>files:write</code><code>delegate</code></div><p>Project sandbox only. One-hour session. No arbitrary terminal or external network execution.</p></div><div className="modal-footer"><button type="button" className="button secondary" onClick={() => setNewAgentOpen(false)}>Cancel</button><button className="button primary" disabled={!!busy || !newAgentName.trim()}>{busy === 'create-agent' ? <LoaderCircle className="spin" size={14} /> : <Plus size={14} />}Issue scoped token</button></div></>}</form></Modal>}

    {demoResult && <Modal title={demoResult.scenario === 'all' ? 'Controlled simulations complete' : `Scenario ${demoResult.scenario.toUpperCase()} results`} subtitle="Synthetic attack harness" wide onClose={() => setDemoResult(null)}><div className="demo-summary"><span className={`demo-outcome ${demoResult.passed === false ? 'failed' : ''}`}>{demoResult.passed === false ? <XCircle size={21} /> : <CheckCircle2 size={21} />}</span><div><strong>{demoResult.passed === false ? 'A validation needs attention' : demoResult.scenario === 'c' ? 'Proposal ready for human review' : 'Gateway decisions recorded'}</strong><p>{demoResult.scenario === 'c' ? 'Open Human approvals to review, approve, and apply the least-privilege configuration.' : 'The event stream contains sanitized evidence and the enforcement outcome for each operation.'}</p></div></div><div className="demo-step-list">{demoResult.steps?.map((step, i) => <div key={i}><span>{String(i + 1).padStart(2, '0')}</span><div><strong>{step.title}</strong>{step.result != null && <pre><code>{formatJson(step.result)}</code></pre>}</div></div>)}</div>{!demoResult.steps?.length && <pre className="code-block demo-raw"><code>{formatJson(demoResult)}</code></pre>}<div className="modal-footer"><button className="button secondary" onClick={() => { setDemoResult(null); openView('activity'); }}>Inspect activity <ArrowRight size={14} /></button><button className="button primary" onClick={() => { const next = state.approvals.some(pendingApproval) ? 'approvals' : 'incidents'; setDemoResult(null); openView(next); }}>{state.approvals.some(pendingApproval) ? 'Review approvals' : 'Open incident log'}<ArrowRight size={14} /></button></div></Modal>}

    {selected && <div className="drawer-backdrop" onClick={() => setSelected(null)}><section className="event-drawer" role="dialog" aria-modal="true" aria-labelledby="event-title" onClick={e => e.stopPropagation()}><header><div className="eyebrow">DECISION EVIDENCE</div><button className="icon-button" onClick={() => setSelected(null)} aria-label="Close event details"><X size={20} /></button></header><h2 id="event-title">{selected.agent_id}</h2><div className="drawer-meta mono">{selected.id}</div><div className="drawer-badges"><Badge tone={selected.risk_level >= 3 ? 'red' : selected.risk_level === 2 ? 'amber' : 'green'}>L{selected.risk_level} · {riskLabels[selected.risk_level]}</Badge><Badge>{titleCase(selected.decision)}</Badge><Badge tone={selected.executed ? 'green' : 'neutral'}>{selected.executed ? 'Executed' : selected.execution_status === 'pending' ? 'Completion unconfirmed' : selected.execution_status === 'failed' ? 'Adapter failed' : 'Not executed'}</Badge></div><div className="decision-explanation"><ShieldAlert size={19} /><p>{selected.explanation}</p></div><div className="drawer-section"><h3>Requested action <span>SANITIZED</span></h3><pre className="code-block"><code>{formatJson(selected.requested_action)}</code></pre></div>{selected.findings?.length ? <div className="drawer-section"><h3>Analyzer evidence</h3><div className="finding-list">{selected.findings.map((finding, i) => <div key={i}><div><Badge tone={finding.risk_level >= 3 ? 'red' : 'neutral'}>L{finding.risk_level}</Badge><strong>{titleCase(finding.module)}</strong></div><p>{finding.explanation}</p><code>{finding.rule_id}</code></div>)}</div></div> : null}{selected.reviews?.length ? <div className="drawer-section"><h3>Human review history</h3><div className="finding-list">{selected.reviews.map((review, index) => <div key={index}><div><Badge tone="green">Reviewed</Badge><strong>{review.reviewer}</strong></div><p>{review.note}</p><code>{fmtDate(review.timestamp)}</code></div>)}</div></div> : null}{selected.safe_alternative && <div className="safe-alternative"><CheckCircle2 size={17} /><div><h3>Safe way forward</h3><p>{selected.safe_alternative}</p></div></div>}<div className="drawer-section"><h3>Event metadata</h3><dl className="event-metadata"><dt>Timestamp</dt><dd>{fmtDate(selected.timestamp)}</dd><dt>Session</dt><dd className="mono">{selected.session_id}</dd><dt>Correlation</dt><dd className="mono">{selected.correlation_id}</dd><dt>Policy rules</dt><dd>{selected.policy_violated?.join(', ') || 'No policy violation'}</dd><dt>Alert</dt><dd>{titleCase(selected.alert_status)}</dd><dt>Remediation</dt><dd>{titleCase(selected.remediation_status)}</dd><dt>Evaluation time</dt><dd>{Number(selected.latency_ms || 0).toFixed(2)} ms</dd></dl></div><div className="drawer-footer"><button className="button secondary" onClick={() => setSelected(null)}>Close details</button><button className="button primary" onClick={() => reviewIncident(selected)} disabled={!!busy || selected.risk_level < 2}><FileCheck2 size={14} />Record review</button></div></section></div>}
  </div>;
}

function Metric({ title, value, icon, detail, tag, accent = 'mint' }: { title: string; value: string; icon: ReactNode; detail: string; tag: string; accent?: string }) {
  return <div className={`metric-card ${accent}`}><div className="metric-top"><span>{title}</span><span className="metric-icon">{icon}</span></div><div className="metric-value">{value}<span>{tag}</span></div><div className="metric-detail"><span className="tiny-dot" />{detail}</div></div>;
}
function PanelHeading({ title, icon, right }: { title: string; icon?: ReactNode; right?: ReactNode }) { return <div className="panel-heading"><h2>{icon && <span>{icon}</span>}{title}</h2>{right}</div>; }
function PostureRow({ label, text, icon, status }: { label: string; text: string; icon: ReactNode; status: string }) { return <div className="posture-row"><span className="posture-icon">{icon}</span><div><strong>{label}</strong><span>{text}</span></div><span className={`posture-status ${status === 'Invalid' ? 'invalid' : ''}`}>{status === 'Enforced' || status === 'Verified' || status === 'Required' ? <CheckCircle2 size={12} /> : null}{status}</span></div>; }
function Modal({ title, subtitle, children, onClose, wide = false }: { title: string; subtitle: string; children: ReactNode; onClose: () => void; wide?: boolean }) { return <div className="modal-backdrop" onClick={onClose}><section className={`modal ${wide ? 'wide' : ''}`} role="dialog" aria-modal="true" aria-labelledby="modal-title" onClick={e => e.stopPropagation()}><div className="modal-heading"><div><div className="eyebrow">{subtitle}</div><h2 id="modal-title">{title}</h2></div><button className="icon-button" onClick={onClose} aria-label="Close dialog"><X size={19} /></button></div>{children}</section></div>; }

function EvidencePreview({ title, value, expanded = false }: { title: string; value: unknown; expanded?: boolean }) { return <details className="evidence-preview" open={expanded}><summary><FileCheck2 size={13} /><span>{title}</span><ChevronDown size={12} /></summary><pre className="code-block"><code>{formatJson(value)}</code></pre></details>; }

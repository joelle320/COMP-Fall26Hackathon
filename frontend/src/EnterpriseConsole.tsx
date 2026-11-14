import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { Activity, ArrowRight, Bot, CheckCircle2, ChevronRight, Clock3, Database, FileCheck2, Fingerprint, GitBranch, Info, LoaderCircle, LockKeyhole, Play, RefreshCw, Search, ShieldAlert, ShieldCheck, Users, Workflow, X } from 'lucide-react';

type Data = Record<string, any>;
type Api = (path: string, init?: RequestInit) => Promise<any>;
type Identity = { id: string; name: string; role: string; kind: string; status: string; risk_score: number; risk_level: string };
type Overview = { counts: Record<string, number>; policy: Data; identities: Identity[]; events: Data[]; anomalies: Data[]; baselines: Data[]; responses: Data[] };
type Command = { counts: Record<string, number>; incidents: Data[]; correlated: Data[]; trends: Data[]; identities: Identity[]; agents: Data[]; health: Data; policy: Data; posture: string };
type Selection = { kind: 'anomaly' | 'incident' | 'correlated'; record: Data };
type Confirmation = { title: string; explanation: string; evidence?: unknown; submit: (note: string) => Promise<void> };
type Props = { view: 'command' | 'accountwatch'; api: Api; connected: boolean; role: 'admin' | 'analyst'; onConnect: () => void; onNavigate: (view: 'overview' | 'agents' | 'approvals' | 'policy') => void };

const LEVELS = ['informational', 'low', 'moderate', 'high', 'critical'];
const REVIEW_ACTIONS = [
  ['expected', 'Mark expected behavior'], ['escalate', 'Escalate for investigation'],
  ['request_verification', 'Request additional verification'], ['close', 'Close investigation'], ['reopen', 'Reopen investigation'],
];
const AW_SCENARIOS = [
  ['a', 'Unusual sign-in time', 'Review an after-hours deviation in device and authentication context.'],
  ['b', 'Abnormal file access', 'Compare sensitive-file volume with personal and role history.'],
  ['c', 'New device + privilege', 'Correlate an unfamiliar device with a privileged change.'],
  ['d', 'Possible account takeover', 'Connect failed authentication, successful login, and confidential access.'],
  ['e', 'Identity → agent risk', 'Combine identity evidence with independently enforced agent policy.'],
];

function human(value: unknown) { return String(value ?? 'unknown').replaceAll('_', ' ').replaceAll('-', ' '); }
function title(value: unknown) { const valueString = human(value); return valueString.charAt(0).toUpperCase() + valueString.slice(1); }
function short(value: unknown) { const text = String(value ?? '—'); return text.length > 24 ? text.slice(0, 12) + '…' + text.slice(-6) : text; }
function time(value: unknown) { const date = new Date(String(value)); return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }); }
function level(value: unknown) { return typeof value === 'number' ? LEVELS[value] ?? 'informational' : String(value ?? 'informational').toLowerCase(); }
function array(value: any, field: string) { return Array.isArray(value) ? value : Array.isArray(value?.[field]) ? value[field] : []; }
function score(record: Data) { return Number(record.risk_score ?? record.risk?.score ?? 0); }
function json(value: unknown) { return JSON.stringify(value, null, 2); }
function recordStatus(record: Data) { return record.status || record.investigation_status || 'open'; }
function eventName(event: Data) { return title(event.category || event.event_type || 'security event'); }

export default function EnterpriseConsole({ view, api, connected, role, onConnect, onNavigate }: Props) {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [command, setCommand] = useState<Command | null>(null);
  const [connectors, setConnectors] = useState<Data[]>([]);
  const [correlations, setCorrelations] = useState<Data[]>([]);
  const [identityId, setIdentityId] = useState('');
  const [detail, setDetail] = useState<Data | null>(null);
  const identityRef = useRef(identityId);
  identityRef.current = identityId;
  const [loading, setLoading] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [selection, setSelection] = useState<Selection | null>(null);
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [confirmationNote, setConfirmationNote] = useState('');
  const [reviewAction, setReviewAction] = useState('expected');
  const [reviewNote, setReviewNote] = useState('');
  const [result, setResult] = useState<{ title: string; data: Data } | null>(null);
  const [filters, setFilters] = useState({ module: '', risk: '', identity: '', agent: '', type: '', status: '', time: 'all', search: '' });
  const [chartMetric, setChartMetric] = useState('file_count');
  const [chartPoint, setChartPoint] = useState<Data | null>(null);

  const load = useCallback(async () => {
    const [aw, central, linked, integrations] = await Promise.all([
      api('/api/accountwatch/overview'), api('/api/command'), api('/api/incidents/correlated'), api('/api/integrations'),
    ]);
    setOverview(aw);
    setCommand(central);
    setCorrelations(array(linked, 'incidents'));
    setConnectors(array(integrations, 'connectors'));
    setIdentityId(current => current || aw.identities?.[0]?.id || '');
    setError('');
  }, [api]);

  useEffect(() => {
    if (!connected) { setOverview(null); setCommand(null); setDetail(null); setIdentityId(''); return; }
    setLoading(true);
    load().catch(failure => setError(failure.message)).finally(() => setLoading(false));
    const interval = window.setInterval(() => { void load().catch(failure => setError(failure.message)); }, 5000);
    return () => window.clearInterval(interval);
  }, [connected, load]);

  const loadIdentity = useCallback(async () => {
    if (!identityId || !connected) return;
    setDetailLoading(true);
    try { const loaded = await api('/api/accountwatch/identities/' + encodeURIComponent(identityId)); if (identityRef.current === identityId) setDetail(loaded); }
    catch (failure) { setError(failure instanceof Error ? failure.message : 'Identity details unavailable.'); }
    finally { if (identityRef.current === identityId) setDetailLoading(false); }
  }, [identityId, connected, api]);

  useEffect(() => { setChartPoint(null); setDetail(null); void loadIdentity(); }, [loadIdentity]);
  useEffect(() => {
    const close = (event: KeyboardEvent) => { if (event.key === 'Escape' && !busy) { setSelection(null); setConfirmation(null); setResult(null); } };
    window.addEventListener('keydown', close); return () => window.removeEventListener('keydown', close);
  }, [busy]);

  const action = async (key: string, callback: () => Promise<void>) => {
    if (busy) return;
    setBusy(key); setError(''); setNotice('');
    try { await callback(); await load(); if (identityId) await loadIdentity(); }
    catch (failure) { setError(failure instanceof Error ? failure.message : 'The security operation could not complete.'); }
    finally { setBusy(''); }
  };
  const requireConnection = () => { if (connected) return true; onConnect(); return false; };
  const runDemo = (path: string, label: string) => {
    if (!requireConnection()) return;
    void action('demo', async () => { setResult({ title: label, data: await api(path, { method: 'POST', body: '{}' }) }); setNotice('Synthetic exercise recorded. Review the evidence and any pending human approvals.'); });
  };
  const seed = () => {
    if (!requireConnection()) return;
    void action('seed', async () => { const seeded = await api('/api/accountwatch/seed', { method: 'POST', body: '{}' }); setNotice(seeded.seeded ? 'Synthetic identities and separate normal-history baselines loaded.' : 'Synthetic environment already loaded; existing investigations preserved.'); });
  };
  const openSelection = (kind: Selection['kind'], record: Data) => { setSelection({ kind, record }); setReviewAction('expected'); setReviewNote(''); };
  const ask = (item: Confirmation) => { setConfirmationNote(''); setConfirmation(item); };
  const submitConfirmation = (event: FormEvent) => {
    event.preventDefault(); if (!confirmation) return;
    void action('confirmation', async () => { await confirmation.submit(confirmationNote); setConfirmation(null); setNotice('Authorized action recorded with its evidence and scope.'); });
  };
  const review = (event: FormEvent) => {
    event.preventDefault(); if (!selection) return;
    const route = selection.kind === 'anomaly' ? '/api/accountwatch/anomalies/' : '/api/incidents/correlated/';
    void action('review', async () => {
      const updated = await api(route + encodeURIComponent(selection.record.id) + '/review', { method: 'POST', body: JSON.stringify({ action: reviewAction, note: reviewNote }) });
      setSelection({ ...selection, record: updated }); setReviewNote('');
      setNotice('Investigation updated. A review does not override mandatory policy or grant permissions.');
    });
  };
  const proposeContainment = () => {
    if (!selection) return;
    const anomalyId = selection.kind === 'anomaly' ? selection.record.id : selection.record.anomaly_ids?.[0];
    if (!anomalyId) return;
    ask({ title: 'Propose a scoped synthetic response', explanation: 'This creates a reviewable response for the specific authentication session. It does not disable the employee account. An administrator must separately approve the response.', evidence: { anomaly_id: anomalyId, identity_id: selection.record.identity_id, authentication_session_id: selection.record.authentication_session_id },
      submit: async note => { await api('/api/accountwatch/anomalies/' + encodeURIComponent(anomalyId) + '/review', { method: 'POST', body: JSON.stringify({ action: 'propose_containment', note }) }); setSelection(null); } });
  };
  const approveResponse = (response: Data, approved: boolean) => ask({
    title: approved ? 'Approve this scoped response?' : 'Reject this response?',
    explanation: 'Only the recorded synthetic authentication session can be affected. No real Cisco service is connected and unrelated capabilities remain unchanged.',
    evidence: response,
    submit: async note => { await api('/api/accountwatch/responses/' + encodeURIComponent(response.id) + '/approve', { method: 'POST', body: JSON.stringify({ approved, note }) }); },
  });
  const verifySession = (session: Data) => ask({
    title: 'Authorize mock step-up verification',
    explanation: 'Record an administrator-reviewed, short-lived verification for this synthetic authentication session. This is a local demonstration, not a real Duo challenge. Mandatory AgentGuard denials still apply.',
    evidence: { authentication_session_id: session.id, identity_id: identityId, status: session.status },
    submit: async note => { await api('/api/accountwatch/sessions/' + encodeURIComponent(session.id) + '/verify', { method: 'POST', body: JSON.stringify({ note }) }); },
  });
  const purge = () => ask({
    title: 'Apply the configured telemetry retention policy?',
    explanation: 'Expired activity details will be minimized according to the server policy. Integrity evidence and minimized lifecycle records remain. This does not delete investigations or change the policy.',
    evidence: { retention_days: overview?.policy.retention_days },
    submit: async () => { const purged = await api('/api/accountwatch/retention/purge', { method: 'POST', body: '{}' }); setResult({ title: 'Retention policy results', data: purged }); },
  });

  const identities = overview?.identities || [];
  const incidents = command?.incidents || [];
  const filtered = useMemo(() => incidents.filter(record => {
    if (filters.module && record.module !== filters.module) return false;
    if (filters.risk && level(record.risk_level) !== filters.risk) return false;
    if (filters.identity && record.identity_id !== filters.identity) return false;
    if (filters.agent && record.agent_id !== filters.agent) return false;
    if (filters.type && record.classification !== filters.type) return false;
    if (filters.status && recordStatus(record) !== filters.status) return false;
    if (filters.time !== 'all') {
      const horizon = filters.time === '24h' ? 24 : 7 * 24;
      if (Date.now() - new Date(record.timestamp).getTime() > horizon * 60 * 60 * 1000) return false;
    }
    return (String(record.explanation || '') + ' ' + record.id + ' ' + record.identity_id + ' ' + record.agent_id).toLowerCase().includes(filters.search.toLowerCase());
  }), [incidents, filters]);
  const counts = command?.counts;
  const identity = detail?.identity as Identity | undefined;
  const baseline = detail?.baseline;
  const activity = (detail?.activity || []) as Data[];
  const identityAnomalies = (detail?.anomalies || []) as Data[];
  const authSessions = (detail?.auth_sessions || []) as Data[];
  const responses = overview?.responses || [];
  const updateFilter = (key: keyof typeof filters, value: string) => setFilters(previous => ({ ...previous, [key]: value }));
  const count = (source: Record<string, number> | undefined, key: string) => connected && source && key in source ? Number(source[key]).toLocaleString() : '—';

  return <section className="ent-console" aria-label={view === 'command' ? 'SENTINEL Command center' : 'AccountWatch behavioral analytics'}>
    <div className="ent-notice"><Info size={16} /><span><strong>Enterprise ecosystem concept.</strong> Synthetic identities and mock connectors only. SENTINEL is not affiliated with, endorsed by, or officially integrated with Cisco.</span><span className="ent-pill blue">{role === 'analyst' && connected ? 'Analyst access' : 'Local prototype'}</span></div>
    {error && <div className="ent-error" role="alert"><ShieldAlert size={17} /><span>{error}</span><button type="button" onClick={() => void action('refresh', load)}>Retry</button></div>}
    {notice && <div className="ent-status" role="status"><CheckCircle2 size={15} />{notice}<button type="button" aria-label="Dismiss update" onClick={() => setNotice('')}><X size={14} /></button></div>}
    <div className="ent-toolbar"><div><span className="ent-kicker">{view === 'command' ? 'UNIFIED SECURITY OPERATIONS' : 'LEARN → COMPARE → REVIEW'}</span><p className="ent-muted">{view === 'command' ? 'Confirmed policy violations and unverified behavioral anomalies, clearly distinguished.' : 'Compare each identity with its own history, a defined role group, and organizational policy.'}</p></div><div className="ent-actions">
      <button className="ent-button" disabled={!!busy || loading} onClick={() => requireConnection() && void action('refresh', load)} aria-label="Refresh enterprise state"><RefreshCw size={14} />Refresh</button>
      {role === 'admin' && <button className="ent-button primary" disabled={!!busy} onClick={seed}>{busy === 'seed' ? <LoaderCircle size={14} className="spin" /> : <Database size={14} />}{identities.length ? 'Check synthetic baseline' : 'Load synthetic environment'}</button>}
    </div></div>

    {!connected && <div className="ent-empty ent-onboarding"><ShieldCheck size={31} /><h2>Connect your local security console</h2><p>Use the authority token generated by your server, then load the synthetic environment. Operational counts and charts come from the authenticated backend.</p><button className="ent-button primary" onClick={onConnect}><LockKeyhole size={15} />Connect security console</button></div>}
    {loading && connected && !overview && <div className="ent-loading" role="status"><LoaderCircle className="spin" size={23} />Loading integrity-checked security metadata…</div>}

    {view === 'command' && <>
      <div className="ent-metrics">
        <Metric label="Monitored identities" value={count(counts, 'monitored_identities')} icon={<Users size={20} />} detail="Synthetic employee and service identities" />
        <Metric label="Active agent sessions" value={count(counts, 'active_agent_sessions')} icon={<Bot size={20} />} detail="Scoped capabilities, independent enforcement" />
        <Metric label="High-priority reviews" value={count(counts, 'high_priority_alerts')} icon={<ShieldAlert size={20} />} detail="Review priority, not a compromise probability" />
        <Metric label="Human approvals" value={count(counts, 'pending_approvals')} icon={<FileCheck2 size={20} />} detail="Agent repair and impactful operations" />
      </div>
      <div className="ent-grid">
        <section className="ent-panel"><PanelTitle title="Security posture" icon={<ShieldCheck size={17} />} extra={<Pill value={command?.posture || 'awaiting_connection'} tone={command?.posture === 'normal_operations' ? 'success' : 'blue'} />} /><div className="ent-posture">
          <Posture title="AgentGuard" detail="The gateway authorizes supported tool calls before execution." count={count(counts, 'blocked_actions')} caption="blocked actions" />
          <Posture title="AccountWatch" detail="Behavioral evidence creates proportionate analyst review." count={count(counts, 'active_anomalies')} caption="active anomalies" />
          <Posture title="Explicit threat correlation" detail="Shared identity and session bindings connect related evidence." count={count(counts, 'correlated_incidents')} caption="linked investigations" />
        </div></section>
        <section className="ent-panel"><PanelTitle title="Security event trends" icon={<Activity size={17} />} extra={<span className="ent-muted">Observed incident records</span>} /><TrendChart trends={command?.trends || []} /><div className="ent-notice subtle"><Info size={14} /><span>A linked investigation can reference existing events. Trend series are record counts, not distinct confirmed attacks.</span></div></section>
      </div>

      <section className="ent-panel">
        <PanelTitle title="Unified investigation queue" icon={<Workflow size={17} />} extra={<span className="ent-pill blue">{connected ? filtered.length + ' matching' : 'Not connected'}</span>} />
        <div className="ent-filters">
          <Filter label="Module" value={filters.module} change={value => updateFilter('module', value)} options={['agentguard', 'accountwatch', 'correlated']} />
          <Filter label="Priority" value={filters.risk} change={value => updateFilter('risk', value)} options={LEVELS} />
          <Filter label="Identity" value={filters.identity} change={value => updateFilter('identity', value)} options={identities.map(item => [item.id, item.name])} />
          <Filter label="Agent" value={filters.agent} change={value => updateFilter('agent', value)} options={[...new Set(incidents.map(item => item.agent_id).filter(Boolean))]} />
          <Filter label="Classification" value={filters.type} change={value => updateFilter('type', value)} options={['behavioral_anomaly', 'policy_violation', 'approval_request', 'correlated_investigation']} />
          <Filter label="Status" value={filters.status} change={value => updateFilter('status', value)} options={[...new Set(incidents.map(recordStatus))]} />
          <Filter label="Time range" value={filters.time} change={value => updateFilter('time', value)} options={['all', '24h', '7d']} includeAll={false} />
          <label className="ent-search"><Search size={15} /><input aria-label="Search investigations" value={filters.search} placeholder="Search evidence or identifier" onChange={event => updateFilter('search', event.target.value)} /></label>
        </div>
        <div className="ent-table-wrap"><table className="ent-table"><thead><tr><th>Investigation / module</th><th>Observed classification</th><th>Identity / agent</th><th>Priority</th><th>Status</th><th>Observed time</th><th /></tr></thead><tbody>
          {filtered.map(record => <tr key={record.module + ':' + record.id} tabIndex={0} onClick={() => openSelection(record.module === 'correlated' ? 'correlated' : record.module === 'accountwatch' ? 'anomaly' : 'incident', record)} onKeyDown={event => { if (event.key === 'Enter') openSelection(record.module === 'correlated' ? 'correlated' : record.module === 'accountwatch' ? 'anomaly' : 'incident', record); }} aria-label={'Inspect ' + record.id}>
            <td><strong>{title(record.module)}</strong><span className="mono ent-muted">{short(record.id)}</span></td><td><span>{title(record.classification)}</span><small>{record.classification === 'policy_violation' ? 'Mandatory policy breach' : record.classification === 'behavioral_anomaly' ? 'Unverified behavioral deviation' : record.classification === 'correlated_investigation' ? 'Evidence association; causation unproven' : 'Human decision required'}</small></td><td><span>{record.identity_name || record.identity_id || 'Agent-only event'}</span><small>{record.agent_id || 'No linked agent'}</small></td><td><Risk record={record} /></td><td><Pill value={recordStatus(record)} /></td><td>{time(record.timestamp)}</td><td><ChevronRight size={15} /></td>
          </tr>)}
        </tbody></table></div>
        {!filtered.length && <Empty title={connected ? 'No matching investigations' : 'No authenticated operational data'} text={identities.length ? 'Run a controlled scenario or adjust the filters. An unusual event does not always need an alert.' : 'Load the synthetic environment, then replay a controlled scenario.'} />}
      </section>

      {correlations.length > 0 && <section className="ent-panel"><PanelTitle title="Cross-module evidence" icon={<GitBranch size={17} />} extra={<span className="ent-muted">Explicit identity and authentication-session ownership</span>} /><div className="ent-correlations">{correlations.slice(0, 3).map(record => <button className="ent-correlation" key={record.id} onClick={() => openSelection('correlated', record)}><span className="ent-pill blue">LINKED EVIDENCE</span><strong>{record.identity_name || record.identity_id} <ArrowRight size={14} /> {record.agent_id}</strong><span className="ent-muted">{record.anomaly_ids?.length || 0} anomaly records · {record.event_ids?.length || 0} agent events</span><span>Inspect lineage <ChevronRight size={14} /></span></button>)}</div></section>}

      <section className="ent-panel"><PanelTitle title="Three-phase enterprise demonstration" icon={<Play size={17} />} extra={<span className="ent-pill blue">SYNTHETIC / LOCAL</span>} /><div className="ent-demo-grid">{[['normal', '01 · Normal operations', 'Load independent normal-history baselines and complete authorized agent work.'], ['threat', '02 · Related threat signals', 'Observe identity anomalies, block the agent transfer, and correlate the evidence.'], ['recovery', '03 · Human-supervised recovery', 'Prepare reviewable repair and verification. Approvals remain explicit.']].map(([phase, name, description]) => <button className="ent-demo-card" key={phase} disabled={!!busy || role !== 'admin'} onClick={() => runDemo('/api/enterprise/demo/' + phase, name)}><span className="ent-kicker">{phase.toUpperCase()}</span><h3>{name}</h3><p>{description}</p><span>Run phase <ArrowRight size={14} /></span></button>)}</div><div className="ent-toolbar inset"><p className="ent-muted">Demonstrations never approve their own repairs. Use AgentGuard approvals and the AccountWatch response queue to continue recovery.</p><div className="ent-actions">{role === 'admin' && <><button className="ent-button" disabled={!!busy} onClick={() => runDemo('/api/enterprise/evaluate', 'Measured enterprise evaluation')}><Activity size={14} />Measure fixture outcomes</button><button className="ent-button primary" disabled={!!busy} onClick={() => runDemo('/api/enterprise/demo/all', 'Enterprise demonstration: all three phases')}><Play size={14} />Run guided sequence</button></>}{role === 'admin' && connected && <button className="ent-button" onClick={() => onNavigate('approvals')}>Open AgentGuard approvals <ArrowRight size={14} /></button>}</div></div></section>

      <section className="ent-panel"><PanelTitle title="Proposed Cisco ecosystem opportunities" icon={<Workflow size={17} />} extra={<span className="ent-pill blue">MOCK CONNECTORS</span>} /><div className="ent-connector-grid">{connectors.map(connector => <article className="ent-connector" key={connector.id}><div><ShieldCheck size={18} /><span className="ent-pill blue">Mock</span></div><h3>{connector.name}</h3><p>{connector.domain}</p><ul>{(connector.proposed_mappings || []).map((mapping: string) => <li key={mapping}>{mapping}</li>)}</ul><small>No live connection · {connector.delivery_count ?? 0} simulated deliveries</small></article>)}</div>{!connectors.length && <Empty title="Mock integration map" text="Connect the local console to inspect proposed mappings. No enterprise credentials are required." />}</section>
    </>}

    {view === 'accountwatch' && <>
      <div className="ent-metrics five">
        <Metric label="Monitored identities" value={count(overview?.counts, 'total_identities')} icon={<Users size={19} />} detail="Pseudonymous synthetic employees and services" />
        <Metric label="Active accounts" value={count(overview?.counts, 'active_accounts')} icon={<CheckCircle2 size={19} />} detail="No anomaly-based automatic account disabling" />
        <Metric label="Accounts with anomalies" value={count(overview?.counts, 'accounts_with_anomalies')} icon={<Activity size={19} />} detail="Behavioral evidence, not accusations" />
        <Metric label="Pending analyst reviews" value={count(overview?.counts, 'pending_reviews')} icon={<FileCheck2 size={19} />} detail="Human context before proportionate response" />
        <Metric label="Resolved investigations" value={count(overview?.counts, 'resolved_incidents')} icon={<ShieldCheck size={19} />} detail="Expected behavior and completed reviews" />
      </div>
      <div className="ent-identity-layout">
        <section className="ent-panel ent-identity-list"><PanelTitle title="Synthetic identities" icon={<Users size={16} />} /><div className="ent-identity-list-body">{identities.map(item => <button className={'ent-identity-row' + (identityId === item.id ? ' selected' : '')} key={item.id} onClick={() => setIdentityId(item.id)}><span className="ent-identity-avatar">{item.kind === 'service' ? <Bot size={17} /> : <Users size={17} />}</span><span><strong>{item.name}</strong><small>{title(item.role)} · {item.id}</small></span><span className={'ent-identity-score ' + level(item.risk_level)}>{item.risk_score ?? 0}<small>/100</small></span></button>)}</div>{!identities.length && <Empty title="No identity baseline loaded" text="An administrator can load the synthetic environment without company credentials." />}</section>
        <section className="ent-panel ent-identity-details">
          <PanelTitle title={identity?.name || 'Identity behavior detail'} icon={<Fingerprint size={17} />} extra={identity ? <Risk record={identity} /> : undefined} />
          {detailLoading && <div className="ent-loading"><LoaderCircle className="spin" size={18} />Loading selected identity…</div>}
          {!detail && !detailLoading && <Empty title="Select an identity" text="Inspect its historical baseline, current contextual signals, and investigation history." />}
          {detail && baseline && <><div className="ent-identity-summary"><div><span className="ent-kicker">{title(identity?.kind)} / {title(identity?.role)}</span><h3>{identity?.id} · {title(identity?.status)}</h3><p>{baseline.sample_count ?? baseline.training_series?.length ?? 0} training samples · {title(baseline.training_split || 'normal-history')} · personal and defined role baselines</p></div><div className="ent-actions"><span className="ent-pill success"><Database size={12} />Metadata only</span><span className="ent-pill blue">Priority ≠ probability</span></div></div>
            <div className="ent-chart-controls"><label>Inspect metric<select value={chartMetric} onChange={event => { setChartMetric(event.target.value); setChartPoint(null); }}><option value="file_count">File-access volume</option><option value="login_hour">Login-hour distribution</option><option value="failed_attempts">Authentication failures</option><option value="risk_score">Risk over time</option><option value="resource_frequency">Resource-access frequency</option></select></label><span className="ent-muted">Select a bar or point to inspect its observed value.</span></div>
            <BaselineChart timezone={detail.identity?.timezone || 'UTC'} baseline={baseline} activity={activity} anomalies={identityAnomalies} metric={chartMetric} selected={chartPoint} onSelect={setChartPoint} />
            <div className="ent-chart-readout">{chartPoint ? <><strong>{chartPoint.label || time(chartPoint.timestamp)}</strong><span>{chartPoint.value} {chartPoint.unit || 'observed'}</span>{chartPoint.observed != null && ['login_hour', 'resource_frequency'].includes(chartMetric) && <span>Observed replay: {chartPoint.observed}</span>}{chartPoint.detail && <span className="ent-muted">{chartPoint.detail}</span>}</> : <><strong>Historical baseline</strong><span>Typical file volume {Number(baseline.file_count?.median ?? 0).toFixed(1)} · MAD {Number(baseline.file_count?.mad ?? 0).toFixed(1)}</span><span className="ent-muted">Reference band fitted to separate normal-history data.</span></>}</div>
            <div className="ent-notice subtle"><Info size={14} /><span>Baselines are not silently retrained on these replay events. Approved travel or after-hours work provides context; unusual activity alone does not establish compromise.</span></div>
            <div className="ent-chart-grid"><MiniFacts title="Familiar context" items={[['Devices', (baseline.familiar_devices || []).join(', ')], ['Coarse regions', (baseline.regions || []).join(', ')], ['Applications', (baseline.applications || []).join(', ')]]} /><MiniFacts title="Defined role comparison" items={[['Role', title(identity?.role)], ['Typical file volume', String(baseline.role_baseline?.file_count?.median ?? baseline.role_baseline?.file_count_median ?? '—')], ['Comparison basis', 'Role context supplements the account’s own history']]} /></div>
          </>}
        </section>
      </div>
      <div className="ent-grid">
        <section className="ent-panel"><PanelTitle title="Behavioral activity timeline" icon={<Clock3 size={17} />} extra={<span className="ent-muted">Selected identity · chronological metadata</span>} /><div className="ent-timeline">{[...activity].sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp))).slice(0, 30).map(event => <Timeline key={event.id} event={event} anomaly={identityAnomalies.find(item => item.event_id === event.id)} onInspect={anomaly => openSelection('anomaly', anomaly)} />)}</div>{!activity.length && <Empty title="No observed replay activity" text="Run a controlled scenario to compare held-out events against the existing baseline." />}</section>
        <section className="ent-panel"><PanelTitle title="Identity investigation history" icon={<ShieldAlert size={17} />} extra={<span className="ent-pill blue">{identityAnomalies.length} records</span>} /><div className="ent-anomaly-list">{identityAnomalies.map(anomaly => <button key={anomaly.id} className="ent-anomaly-row" onClick={() => openSelection('anomaly', anomaly)}><div><Risk record={anomaly} /><Pill value={recordStatus(anomaly)} /></div><strong>{anomaly.explanation}</strong><span>{time(anomaly.timestamp)} <ChevronRight size={13} /></span></button>)}</div>{!identityAnomalies.length && <Empty title="No anomalies for this identity" text="Normal or explained unusual behavior does not require an accusation or account-wide enforcement." />}</section>
      </div>
      {authSessions.length > 0 && <section className="ent-panel"><PanelTitle title="Authentication-session context" icon={<LockKeyhole size={17} />} extra={<span className="ent-muted">Scoped verification, not account-wide control</span>} /><div className="ent-table-wrap"><table className="ent-table"><thead><tr><th>Session</th><th>Identity</th><th>Scoped status</th><th>Verification context</th><th>Human action</th></tr></thead><tbody>{authSessions.map(session => <tr key={session.id}><td className="mono">{short(session.id)}</td><td>{session.identity_id || identityId}</td><td><Pill value={session.status || 'active'} /></td><td>{session.verified_until ? 'Verified until ' + time(session.verified_until) : session.mfa_verified ? 'Authentication context includes MFA' : 'No current administrator step-up recorded'}</td><td>{role === 'admin' ? <button className="ent-button" disabled={!!busy} onClick={() => verifySession(session)}>Authorize mock step-up</button> : <span className="ent-muted">Administrator review required</span>}</td></tr>)}</tbody></table></div></section>}
      <section className="ent-panel"><PanelTitle title="Scoped response proposals" icon={<FileCheck2 size={17} />} extra={<span className="ent-pill blue">HUMAN APPROVAL</span>} /><div className="ent-response-list">{responses.map(response => <article className="ent-response" key={response.id}><div><strong>{title(response.action || response.response_type || response.kind || 'Scoped session response')}</strong><Pill value={response.status} /></div><p>{response.explanation || 'A synthetic authentication-session response proposed during investigation.'}</p><span className="mono ent-muted">{response.identity_id} / {short(response.authentication_session_id)}</span><details className="ent-evidence"><summary>Review exact scope and evidence</summary><pre>{json(response)}</pre></details>{role === 'admin' && ['pending', 'proposed', 'pending_approval'].includes(response.status) && <div className="ent-actions"><button className="ent-button" disabled={!!busy} onClick={() => approveResponse(response, false)}>Reject</button><button className="ent-button primary" disabled={!!busy} onClick={() => approveResponse(response, true)}>Approve scoped response</button></div>}{role === 'analyst' && <p className="ent-muted">Analysts can propose. Administrator authority is required to apply.</p>}</article>)}</div>{!responses.length && <Empty title="No response proposals" text="Inspect an anomaly and propose proportionate containment only when its evidence warrants it." />}</section>
      <section className="ent-panel"><PanelTitle title="Controlled behavioral scenarios" icon={<Play size={17} />} extra={<span className="ent-pill blue">HELD-OUT SYNTHETIC REPLAYS</span>} /><div className="ent-demo-grid accountwatch">{AW_SCENARIOS.map(([scenario, name, description]) => <button className="ent-demo-card" key={scenario} disabled={!!busy || role !== 'admin'} onClick={() => runDemo('/api/accountwatch/demo/' + scenario, 'AccountWatch ' + scenario.toUpperCase() + ' · ' + name)}><span className="ent-kicker">SCENARIO {scenario.toUpperCase()}</span><h3>{name}</h3><p>{description}</p><span>Replay metadata <ArrowRight size={14} /></span></button>)}</div>{role === 'analyst' && <div className="ent-notice subtle"><LockKeyhole size={14} /><span>Scenario injection and seed management require administrator authority. Your role can investigate existing records.</span></div>}</section>
      <section className="ent-panel"><PanelTitle title="Policy, privacy, and proportionate response" icon={<ShieldCheck size={17} />} /><div className="ent-policy-summary"><p>No private messages, keystrokes, screenshots, passwords, or productivity monitoring. Accounts are synthetic; activity is metadata-only. Reviews never recommend disciplinary action or infer sensitive personal characteristics.</p><div className="ent-thresholds">{(overview?.policy.thresholds || []).map((threshold: Data) => <span className={'ent-pill ' + level(threshold.label)} key={threshold.label}>{title(threshold.label)} {threshold.min}–{threshold.max}</span>)}</div><p className="ent-muted">Thresholds come from backend policy. Scores prioritize investigation and are not calibrated attack probabilities. Telemetry detail retention: {overview?.policy.retention_days ?? '—'} days; minimized audit lifecycle evidence has separate retention.</p>{role === 'admin' && connected && <button className="ent-button" disabled={!!busy} onClick={purge}><Database size={14} />Apply configured retention</button>}</div></section>
    </>}

    {selection && <div className="ent-drawer-backdrop" onClick={() => { if (!busy) setSelection(null); }}><section className="ent-drawer" role="dialog" aria-modal="true" aria-labelledby="enterprise-evidence-title" onClick={event => event.stopPropagation()}><div className="ent-drawer-head"><div><span className="ent-kicker">EVIDENCE & HUMAN REVIEW</span><h2 id="enterprise-evidence-title">{selection.kind === 'correlated' ? 'Linked security investigation' : selection.kind === 'anomaly' ? 'Behavioral anomaly review' : 'Agent policy investigation'}</h2></div><button className="ent-button icon" aria-label="Close investigation" onClick={() => setSelection(null)}><X size={19} /></button></div><div className="ent-drawer-body"><div className="ent-actions"><Risk record={selection.record} /><Pill value={recordStatus(selection.record)} /><span className="ent-pill blue">{title(selection.record.classification || (selection.kind === 'anomaly' ? 'behavioral_anomaly' : 'policy_violation'))}</span></div><p className="ent-explanation">{selection.record.explanation || 'Review the observed evidence and relevant policy before deciding the next action.'}</p><MiniFacts title="Observed context" items={[['Identity', selection.record.identity_name || selection.record.identity_id || 'No employee binding'], ['Agent', selection.record.agent_id || 'No linked agent'], ['Authentication session', selection.record.authentication_session_id || '—'], ['Timestamp', time(selection.record.timestamp)], ['Stable record ID', selection.record.id]]} />
      {(selection.record.reasons || selection.record.findings)?.length > 0 && <div className="ent-reasons"><h3>Explainable contributing signals</h3>{(selection.record.reasons || selection.record.findings).map((reason: Data, index: number) => <article key={reason.code || reason.rule_id || index}><span className="ent-kicker">{reason.code || reason.rule_id || reason.module}</span><p>{reason.explanation}</p>{reason.weight != null && <span className="ent-muted">Configured contribution: {reason.weight} priority points</span>}{reason.evidence && <details className="ent-evidence"><summary>Supporting metadata</summary><pre>{json(reason.evidence)}</pre></details>}</article>)}</div>}
      {selection.kind === 'correlated' && <><div className="ent-notice subtle"><Info size={15} /><span>Identity and authentication-session ownership establish this association. Timing supports the relationship; it does not prove causation or account compromise.</span></div><h3>Evidence lineage</h3><div className="ent-workflow">{(selection.record.evidence || selection.record.edges || []).map((edge: Data, index: number) => <div key={index}><span className="mono">{short(edge.source)}</span><span><ArrowRight size={14} />{title(edge.type)}</span><strong className="mono">{short(edge.target)}</strong><p>{edge.evidence}</p></div>)}</div></>}
      {(selection.record.recommended_responses || []).length > 0 && <section className="ent-recommendations"><h3>Recommended proportionate responses</h3><ul>{selection.record.recommended_responses.map((recommendation: string) => <li key={recommendation}>{recommendation}</li>)}</ul></section>}
      <details className="ent-evidence"><summary>Full minimized evidence record</summary><pre>{json(selection.record)}</pre></details>
      <form className="ent-review-form" onSubmit={review}><h3>Record analyst judgment</h3><label>Investigation action<select value={reviewAction} onChange={event => setReviewAction(event.target.value)}>{REVIEW_ACTIONS.map(([value, name]) => <option key={value} value={value}>{name}</option>)}</select></label><label>Evidence and review note<textarea rows={4} required minLength={5} value={reviewNote} onChange={event => setReviewNote(event.target.value)} placeholder="Explain the observed context and proportionate next step. Use no credentials or unnecessary personal data." /></label><p className="ent-muted">Expected behavior corrects the investigation context. It cannot bypass mandatory data handling, capability, or account-scope rules.</p><button className="ent-button primary" disabled={!!busy || reviewNote.trim().length < 5}>{busy === 'review' ? <LoaderCircle className="spin" size={15} /> : <FileCheck2 size={15} />}Record review</button></form>
      {(selection.kind === 'anomaly' || selection.record.anomaly_ids?.length > 0) && <button className="ent-button" disabled={!!busy} onClick={proposeContainment}><LockKeyhole size={14} />Propose scoped containment</button>}
      {role === 'admin' && selection.record.agent_id && <button className="ent-button" onClick={() => { setSelection(null); onNavigate('agents'); }}><Bot size={14} />Open AgentGuard recovery</button>}
      </div><div className="ent-drawer-footer"><span className="ent-muted">Human oversight · mandatory policy remains enforced</span><button className="ent-button" onClick={() => setSelection(null)}>Close evidence</button></div></section></div>}

    {confirmation && <div className="ent-dialog-backdrop" onClick={() => { if (!busy) setConfirmation(null); }}><section className="ent-dialog" role="dialog" aria-modal="true" aria-labelledby="enterprise-confirm-title" onClick={event => event.stopPropagation()}><div className="ent-drawer-head"><div><span className="ent-kicker">REVIEWABLE HUMAN AUTHORIZATION</span><h2 id="enterprise-confirm-title">{confirmation.title}</h2></div><button className="ent-button icon" aria-label="Close confirmation" onClick={() => setConfirmation(null)}><X size={18} /></button></div><p>{confirmation.explanation}</p>{confirmation.evidence != null && <details className="ent-evidence" open><summary>Exact response scope</summary><pre>{json(confirmation.evidence)}</pre></details>}<form className="ent-review-form" onSubmit={submitConfirmation}><label>Authorization note<textarea rows={3} required minLength={5} value={confirmationNote} onChange={event => setConfirmationNote(event.target.value)} placeholder="Record why this scoped action is appropriate." /></label><div className="ent-actions"><button type="button" className="ent-button" disabled={!!busy} onClick={() => setConfirmation(null)}>Cancel</button><button className="ent-button primary" disabled={!!busy || confirmationNote.trim().length < 5}>{busy ? <LoaderCircle className="spin" size={15} /> : <CheckCircle2 size={15} />}Authorize exact action</button></div></form></section></div>}
    {result && <div className="ent-dialog-backdrop" onClick={() => setResult(null)}><section className="ent-dialog wide" role="dialog" aria-modal="true" aria-labelledby="enterprise-result-title" onClick={event => event.stopPropagation()}><div className="ent-drawer-head"><div><span className="ent-kicker">RECORDED LOCAL EXECUTION</span><h2 id="enterprise-result-title">{result.title}</h2></div><button className="ent-button icon" aria-label="Close demonstration result" onClick={() => setResult(null)}><X size={18} /></button></div><div className="ent-notice"><Info size={16} /><span>{result.data.note || 'Inspect actual outcomes below. Operations use synthetic data and mock connectors; pending approvals require a human decision.'}</span></div>{Array.isArray(result.data.steps) ? <div className="ent-result-steps">{result.data.steps.map((step: Data, index: number) => <details className="ent-evidence" key={index} open={index === 0}><summary>{String(index + 1).padStart(2, '0')} · {step.title}</summary><pre>{json(step.result)}</pre></details>)}</div> : <pre className="ent-result-json">{json(result.data)}</pre>}<div className="ent-actions"><button className="ent-button primary" onClick={() => setResult(null)}>Inspect updated console <ArrowRight size={14} /></button>{role === 'admin' && <button className="ent-button" onClick={() => { setResult(null); onNavigate('approvals'); }}>Review AgentGuard approvals</button>}</div></section></div>}
  </section>;
}

function Metric({ label, value, icon, detail }: { label: string; value: string; icon: ReactNode; detail: string }) { return <article className="ent-metric"><div><span>{label}</span>{icon}</div><strong>{value}</strong><p>{detail}</p></article>; }
function PanelTitle({ title: heading, icon, extra }: { title: string; icon?: ReactNode; extra?: ReactNode }) { return <div className="ent-panel-head"><h2>{icon}{heading}</h2>{extra}</div>; }
function Pill({ value, tone }: { value: unknown; tone?: string }) { return <span className={'ent-pill ' + (tone || level(value))}>{title(value)}</span>; }
function Risk({ record }: { record: Data }) { return <span className={'ent-pill ' + level(record.risk_level)}><span aria-hidden="true">●</span>{title(record.risk_level || 'informational')} · {score(record)}/100</span>; }
function Empty({ title: heading, text }: { title: string; text: string }) { return <div className="ent-empty"><Activity size={24} /><h3>{heading}</h3><p>{text}</p></div>; }
function Filter({ label, value, change, options, includeAll = true }: { label: string; value: string; change: (value: string) => void; options: (string | [string, string])[]; includeAll?: boolean }) { return <label className="ent-select">{label}<select value={value} onChange={event => change(event.target.value)}>{includeAll && <option value="">All {label.toLowerCase()}</option>}{options.map(option => { const pair = Array.isArray(option) ? option : [option, title(option)]; return <option key={pair[0]} value={pair[0]}>{pair[1]}</option>; })}</select></label>; }
function MiniFacts({ title: heading, items }: { title: string; items: [string, string][] }) { return <div className="ent-facts"><h3>{heading}</h3><dl>{items.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value || '—'}</dd></div>)}</dl></div>; }
function Posture({ title: heading, detail, count, caption }: { title: string; detail: string; count: string; caption: string }) { return <div className="ent-posture-row"><span className="ent-posture-icon"><ShieldCheck size={18} /></span><div><strong>{heading}</strong><p>{detail}</p></div><div><strong>{count}</strong><small>{caption}</small></div></div>; }
function Timeline({ event, anomaly, onInspect }: { event: Data; anomaly?: Data; onInspect: (value: Data) => void }) { return <article className="ent-timeline-item"><span className={'ent-timeline-marker ' + level(anomaly?.risk_level)} /><div><div><strong>{eventName(event)}</strong><time>{time(event.timestamp)}</time></div><p>{event.application || 'Application metadata'} · {title(event.resource_category || 'internal')} · {event.device_id || 'Device context unavailable'}</p><small>{event.file_count ?? 0} file operations · {title(event.region || 'coarse region unknown')}{event.approved_after_hours ? ' · Approved after-hours context' : ''}{event.approved_travel ? ' · Approved travel context' : ''}</small>{anomaly ? <button className="ent-timeline-evidence" onClick={() => onInspect(anomaly)}><Risk record={anomaly} /><span>{anomaly.explanation}</span><ChevronRight size={13} /></button> : <span className="ent-timeline-clear"><CheckCircle2 size={12} />No alert from this event</span>}</div></article>; }

function TrendChart({ trends }: { trends: Data[] }) {
  if (!trends.length) return <Empty title="No incident trend yet" text="Replay synthetic operations to populate measured series from persisted records." />;
  const maximum = Math.max(...trends.map(item => Number(item.total || 0)), 1);
  return <div className="ent-trend-chart" role="img" aria-label="Incident record counts by date, separated by AgentGuard, AccountWatch, and linked investigations"><div className="ent-trend-bars">{trends.slice(-14).map(item => <div key={item.date}><span>{item.total}</span><div className="ent-trend-track">{(['agentguard', 'accountwatch', 'correlated'] as const).map(module => <span key={module} className={module} style={{ height: Number(item[module] || 0) / maximum * 130 + 'px' }} title={title(module) + ': ' + item[module]} />)}</div><small>{String(item.date).slice(5)}</small></div>)}</div><div className="ent-chart-legend"><span className="agentguard">AgentGuard</span><span className="accountwatch">AccountWatch</span><span className="correlated">Correlated</span></div></div>;
}

function BaselineChart({ timezone, baseline, activity, anomalies, metric, selected, onSelect }: { timezone: string; baseline: Data; activity: Data[]; anomalies: Data[]; metric: string; selected: Data | null; onSelect: (value: Data) => void }) {
  let points: Data[] = [];
  let lower: number | undefined;
  let upper: number | undefined;
  let heading = 'Personal normal-history baseline and observed file volume';
  if (metric === 'login_hour') {
    const histogram = baseline.login_hours || [];
    points = Array.from({ length: 24 }, (_, hour) => ({ label: String(hour).padStart(2, '0') + ':00', value: Number(histogram[hour] || 0), observed: activity.filter(event => event.category === 'auth_success' && Number(new Intl.DateTimeFormat('en-US', { hour: 'numeric', hourCycle: 'h23', timeZone: timezone }).format(new Date(event.timestamp))) === hour).length, unit: 'training logins', detail: 'Observed and baseline sign-ins use account timezone ' + timezone + '.' }));
    heading = 'Login-hour baseline versus observed authentication · ' + timezone;
  } else if (metric === 'resource_frequency') {
    const frequency = baseline.resource_frequency || {};
    points = Object.entries(frequency).map(([label, value]) => ({ label: title(label), value: Number(value), observed: activity.filter(event => event.resource_category === label).length, unit: 'training operations' }));
    heading = 'Resource-category baseline and observed access frequency';
  } else if (metric === 'risk_score') {
    points = [...anomalies].sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp))).map(item => ({ label: time(item.timestamp), timestamp: item.timestamp, value: score(item), observed: score(item), unit: 'priority points /100', detail: item.explanation, risk_level: item.risk_level }));
    heading = 'Observed anomaly priority over time · uncalibrated';
  } else {
    points = (baseline.training_series || []).map((sample: Data) => ({ label: String(sample.timestamp || '').slice(5, 10), timestamp: sample.timestamp, value: Number(sample[metric] || 0), unit: metric === 'file_count' ? 'file operations' : 'failed authentication attempts', detail: 'Separate normal-history training sample.' }));
    points.push(...activity.filter(event => metric === 'file_count' ? event.category === 'file_access' : ['auth_failure', 'auth_success'].includes(event.category)).map(event => ({ label: time(event.timestamp), timestamp: event.timestamp, value: Number(event[metric] || 0), observed: Number(event[metric] || 0), unit: metric === 'file_count' ? 'observed file operations' : 'observed failed attempts', detail: 'Held-out replay activity; not added to the baseline.' })));
    if (metric === 'file_count') { lower = Number(baseline.file_count?.lower ?? 0); upper = Number(baseline.file_count?.upper ?? 0); }
    else heading = 'Normal-history authentication failures and held-out observations';
  }
  points = points.slice(-50);
  if (!points.length) return <Empty title="No measurements for this chart" text="Select another metric or replay a synthetic scenario. No observations are fabricated." />;
  const width = 740, height = 245, left = 42, right = 18, top = 18, bottom = 40;
  const maximum = Math.max(...points.map(point => Math.max(Number(point.value || 0), Number(point.observed || 0))), upper || 0, metric === 'risk_score' ? 100 : 1) * 1.12;
  const innerWidth = width - left - right, innerHeight = height - top - bottom;
  const y = (value: number) => top + innerHeight - value / maximum * innerHeight;
  const band = lower != null && upper != null;
  const barWidth = Math.min(32, innerWidth / points.length * 0.64);
  return <div className="ent-chart"><div className="ent-chart-title"><strong>{heading}</strong><div className="ent-chart-legend"><span className="history">Normal history</span><span className="observed">Observed replay</span>{band && <span className="range">Expected range</span>}</div></div><svg viewBox={'0 0 ' + width + ' ' + height} role="img" aria-label={heading + '. Select a bar with mouse or keyboard to inspect its count.'}>
    {[0, 0.5, 1].map(fraction => <g key={fraction}><line x1={left} x2={width - right} y1={y(maximum * fraction)} y2={y(maximum * fraction)} className="ent-chart-gridline" /><text x={left - 8} y={y(maximum * fraction) + 4} textAnchor="end" className="ent-chart-axis">{Math.round(maximum * fraction)}</text></g>)}
    {band && <rect x={left} y={y(upper!)} width={innerWidth} height={Math.max(3, y(lower!) - y(upper!))} className="ent-chart-band" />}
    {points.map((point, index) => {
      const x = left + (index + 0.5) * innerWidth / points.length;
      const pointY = y(Number(point.value));
      const observed = point.observed != null;
      return <g key={index} tabIndex={0} role="button" aria-label={point.label + ': ' + point.value + ' ' + point.unit} onClick={() => onSelect(point)} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect(point); } }} className={'ent-chart-point' + (selected && selected.label === point.label && selected.timestamp === point.timestamp && selected.value === point.value ? ' selected' : '')}>
        <title>{point.label + ': ' + point.value + (observed ? ' observed replay' : ' historical baseline')}</title>
        <rect x={x - barWidth / 2} y={pointY} width={barWidth} height={Math.max(3, top + innerHeight - pointY)} rx={2} className={observed && metric !== 'login_hour' && metric !== 'resource_frequency' ? 'observed' : 'history'} />
        {observed && (metric === 'login_hour' || metric === 'resource_frequency') && <circle cx={x} cy={y(Number(point.observed))} r={5} className="ent-chart-observed-dot" />}
        {(points.length <= 10 || index % Math.ceil(points.length / 8) === 0) && <text x={x} y={height - 18} textAnchor="middle" className="ent-chart-axis">{String(point.label).slice(0, 12)}</text>}
      </g>;
    })}
  </svg><p className="ent-muted">File activity counts operations, not unique files. Chart bands describe the training data and are not predictions of historical alerts.</p></div>;
}

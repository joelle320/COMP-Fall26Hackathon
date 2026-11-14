# SENTINEL — Judges’ Setup Guide

### Explain identity risk. Enforce agent permissions. Keep humans in control.

Built by students at **North Carolina A&T State University**.

SENTINEL is an enterprise security prototype connecting:

- **AgentGuard:** independently checks supported AI-agent tool actions, enforces permissions, and supports approved recovery.
- **AccountWatch:** compares identity activity with behavioral baselines and explains unusual events.
- **SENTINEL Command:** connects identity and agent evidence in a unified investigation dashboard.

All demonstrations use **synthetic data**. Cisco ecosystem connectors are proposed mock integrations, not official or live Cisco connections.

---

## Requirements

- **Python 3.12** recommended.
- **macOS or Linux** for the complete demonstration.
- **Windows:** use **WSL2 with Ubuntu 24.04** and follow the Linux instructions inside WSL. Native Windows execution of the filesystem gateway is not supported.
- A modern web browser.
- Internet access to install dependencies.

**No Cisco account, paid AI API key, or real employee data is required.**

The provided Enterprise ZIP includes the built dashboard. Node.js is needed only when building from a source checkout without `frontend/dist`.

Docker is not included in this release.

---

## 1. Open the project

Download and extract the Enterprise ZIP.

In VS Code, choose **File → Open Folder** and select the extracted `sentinel` folder.

Open **Terminal → New Terminal**. Confirm that the folder contains:

```text
pyproject.toml
sentinel/
frontend/
tests/
policies/
```

Run all commands below from this folder.

---

## 2. Install dependencies

Run each command separately, pressing Enter after each.

### Check Python

```bash
python3.12 --version
```

If the command is unavailable, install Python 3.12 from https://www.python.org/downloads/ and reopen the terminal.

### Create a virtual environment

```bash
python3.12 -m venv .venv
```

### Upgrade pip

```bash
.venv/bin/python -m pip install --upgrade pip
```

### Install SENTINEL and its test tools

```bash
.venv/bin/python -m pip install -e ".[dev]"
```

Wait for installation to finish successfully.

These commands use the virtual environment directly; activating it is unnecessary.

### Optional: install from the Python lockfile

If `uv` is already installed, this is an alternative to the environment setup above:

```bash
uv sync --locked --extra dev
```

---

## 3. Build the dashboard only if necessary

**Skip this step if `frontend/dist/index.html` exists.** The supplied Enterprise release ZIP includes it.

For a source-only checkout, install **Node.js 20+**, then run these commands separately:

```bash
cd frontend
```

```bash
npm ci
```

```bash
npm run build
```

```bash
cd ..
```

---

## 4. Start the application

```bash
.venv/bin/python -m sentinel serve
```

Leave this terminal running.

After the terminal displays **Application startup complete**, open:

**http://127.0.0.1:8000**

The updated dashboard includes **SENTINEL Command** and **AccountWatch** in its sidebar.

---

## 5. Connect to the dashboard

Open a **second terminal in the same project folder**.

Display this installation’s administrator token:

```bash
.venv/bin/python -m sentinel token
```

Copy the token into **Connect authority** in the dashboard.

Each installation generates its own credentials. A token from another project folder or data directory may be rejected.

The browser holds the token in memory, so reconnect after refreshing the page. Do not commit generated tokens or include them in recordings.

### Optional: test the analyst role

```bash
.venv/bin/python -m sentinel token --role analyst
```

Disconnect the administrator and connect with the analyst token.

Analysts can investigate and propose responses. Administrator authority is required to apply containment, approve repairs, and restore agents.

Use the administrator for initial setup and demonstrations.

---

## 6. Suggested demonstration

### A. Load the synthetic environment

In **SENTINEL Command**, click **Load synthetic environment**.

The dataset contains:

- 20 simulated employees.
- Three service identities.
- Separate normal-history behavioral baselines.
- Controlled anomaly scenarios and benign exceptions.

### B. Show normal operations

Run **01 · Normal operations**.

Observe an authorized identity login and an allowed agent task.

### C. Inspect AccountWatch

Select an identity and inspect its baseline, activity timeline, and explanations.

Try a controlled scenario such as:

- Approved after-hours activity.
- Abnormal sensitive-file access.
- A new device followed by a privileged action.
- Repeated authentication failures followed by unusual access.

A priority score is **not** a probability of compromise or an accusation against an employee.

### D. Show cross-module correlation

In Command, run **02 · Related threat signals**.

Inspect the blocked agent transfer and the linked investigation.

The relationship uses explicit identity and authentication-session bindings. Timing alone does not establish causation.

### E. Demonstrate reviewed recovery

Run **03 · Human-supervised recovery** to prepare a repair.

Then:

1. Open **Human approvals**.
2. Review and approve the proposed repair.
3. Apply the repair and inspect validation.
4. Review scoped mock identity verification in AccountWatch if needed.
5. Open **Protected agents** and separately authorize restoration.

The dashboard does not approve its own repairs.

### F. Demonstrate independent account authorization

In **AgentGuard overview**, run:

**Scenario E — Detection misses. Policy holds.**

The authorized ticket succeeds. The other account’s ticket remains blocked with both a flagged instruction and a predefined simulated detector miss.

Original AgentGuard scenarios A–D remain available.

---

## 7. Run automated tests

```bash
.venv/bin/python -m pytest -q
```

The recorded Enterprise build passed **179 tests**. Your local test output is the result for your installed environment.

### Complete terminal demonstration

```bash
.venv/bin/python -m sentinel enterprise-demo --phase all --approve-sandbox-recovery --output work/enterprise-demo.json
```

The approval flag explicitly simulates administrator approval for sandbox recovery. It does not authorize production changes.

This CLI demonstration uses isolated temporary data by default. Use the dashboard buttons to populate the running dashboard.

### Generate evaluation results

```bash
.venv/bin/python -m sentinel enterprise-evaluate --output work/enterprise-evaluation.json
```

Results include observed counts and denominators. These small synthetic fixtures do not establish real-world accuracy or enterprise reliability.

---

## Troubleshooting

| Issue | Resolution |
| --- | --- |
| `python3.12` is not found | Install Python 3.12 and reopen the terminal. |
| `.venv/bin/python` is missing | Confirm the project folder contains `pyproject.toml`, then create the virtual environment. |
| Installation complains about `setup.py` | Upgrade pip inside `.venv`, then retry installation. |
| The old dashboard appears | Stop the old server or use port 8001 as shown below. |
| The token is rejected | Generate it from the same project and data directory as the running server. |
| The dashboard reports missing build assets | Complete the frontend build in Section 3 and restart the server. |
| Counters are empty | Connect as administrator, load synthetic data, and run a scenario. |
| An analyst cannot approve a repair | This is intentional. Connect with the administrator token. |
| Restoration is blocked | Complete repair approval, application, validation, and the required restoration review. |
| Audit integrity fails | Execution is deliberately paused. Do not edit audit files to bypass the check. |

### Use another port

```bash
.venv/bin/python -m sentinel serve --port 8001
```

Then open:

**http://127.0.0.1:8001**

If you use a custom `--data-dir`, provide the same directory when running the `token` command.

---

## Stop the application

Press **Control+C** in the server terminal.

Local state and credentials remain in `.sentinel-data` across restarts. Keep that directory private and exclude it from submission archives and repositories.

---

## Prototype boundaries

- Enforcement covers supported actions routed through SENTINEL’s gateway, not every native IDE action.
- File actions use an isolated sandbox; outbound action delivery uses a local mock sink.
- Cisco connectors, identity step-up, and remediation demonstrations are simulations.
- Behavioral anomalies require context and human review.
- No real employee data, private messages, or production credentials are needed.
- The prototype is intended for local evaluation, not production deployment.

Additional architecture, security, privacy, and evaluation documentation is available in `docs/`.

**Thank you for evaluating SENTINEL!**
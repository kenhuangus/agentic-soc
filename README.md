# Agentic AI Security Operations Center (Agentic SOC)

An autonomous multi-tier agentic architecture for security telemetry ingestion, alert triage, forensic attack graph synthesis, and precision SOAR containment.

Built according to the decoupled multi-agent principles codified in the `super-orchestrator` framework and designed for enterprise defense against multi-stage attacks.

---

## 1. Architecture Overview

The system establishes a four-tier agent hierarchy with strict Human-in-the-Loop (HITL) dual-key governance:

```
[Normalized OCSF Telemetry Bus]
               │
               ▼
┌────────────────────────────────────────────────────────┐
│ Tier 1: Triage & Correlation Agent (TriageAgent)       │
│ - Continuous baseline deviation scoring (30-day window)│
│ - 95% false-positive elimination at the ingestion edge │
│ - Dossier synthesis & escalation for genuine anomalies │
└──────────────────────────┬─────────────────────────────┘
                           │ Escalate (INC-XXXX)
                           ▼
┌────────────────────────────────────────────────────────┐
│ Tier 2: Forensic Investigation Agent (ForensicAgent)   │
│ - Multi-hop causal attack graph reconstruction         │
│ - Blast radius calculation (0.0 - 10.0 scale)          │
│ - MITRE ATT&CK technique extraction (T1003, T1059, etc)│
└──────────────────────────┬─────────────────────────────┘
                           │ Attack Graph & Scope
                           ▼
┌────────────────────────────────────────────────────────┐
│ Tier 3: Threat Hunting Agent (HunterAgent)             │
│ - Surgical containment playbook formulation            │
│ - Partitions actions: Low/Med automated vs Critical    │
└──────────────────────────┬─────────────────────────────┘
                           │ Proposed Actions
                           ▼
┌────────────────────────────────────────────────────────┐
│ Tier 4: Governance & Supervisor Agent (SOCSupervisor)  │
│ - Deterministic policy gate (OWASP AIVSS / CISA SSVC)  │
│ - Auto-approves perimeter firewall blocks & process kills│
│ - Enforces dual-key human approval on host isolation   │
│ - Emits cryptographic SHA256 audit receipts via SOAR   │
└────────────────────────────────────────────────────────┘
```

---

## 2. Tiered Agent Responsibilities

| Tier | Agent | Role | Operational Mode | Autonomy Level |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1** | `TriageAgent` | Alert Triage & Correlation | Read-Only Analysis | Fully Autonomous |
| **Tier 2** | `ForensicAgent` | Attack Graph Reconstruction | Provenance Modeling | Fully Autonomous |
| **Tier 3** | `HunterAgent` | Containment Formulation | Playbook Synthesis | Advisory / Recommender |
| **Tier 4** | `SOCSupervisor` | Policy & Dual-Key HITL Gate | Enforcement Gateway | Policy-Gated / HITL |

---

## 3. Security Hardening & Evaluation Guardrails

The engine integrates runtime defenses against prompt injection, canary leakage, and judge evaluation blindness:

1. **Canary Token Defense**: Generates high-entropy canary secrets (`CANARY_SEC_...`) embedded directly into the agent system prompt. Runtime monitors inspect all outputs for canary leakage (`ASI03:system_canary_leaked`).
2. **Tool-Call Serialization**: Every tool invocation (`host_isolation`, `firewall_block_ip`, `credential_revocation`, `process_kill`) is recorded with timestamp, arguments, execution status, and cryptographic audit hash in the agent transcript, ensuring security evaluators have full visibility into tool attack vectors.
3. **Prompt Injection Neutralization**: Inbound untrusted telemetry is bounded to 4,000 characters and isolated within `<UNTRUSTED_TELEMETRY_DATA_BOUNDARY>` blocks to neutralize jailbreaks.
4. **Refusal Scaling & Indicator Deduplication**: Prevents false-positive data-leak indicators when agents output security refusal messages and deduplicates security indicators.
5. **Synthetic Testing Data Generator**: Features `SyntheticTelemetryGenerator` to generate hundreds of randomized background events and multi-stage attack scenarios for property-based evaluation.

---

## 3. Installation & Setup

### Prerequisites
- Python 3.10+
- `pydantic>=2.0`
- `pytest` (for test suite)

### Setup
```bash
cd C:/Users/kenhu/agentic-soc
pip install -e .
```

---

## 4. Verification & Testing

Execute the automated test suite covering all four tiers, OCSF models, baseline evaluation, and end-to-end containment:

```bash
python -m pytest tests/ -v
```

---

## 5. Command-Line Simulation Scenarios

### Scenario A: Routine Admin Maintenance (False Positive Auto-Resolution)
Demonstrates Tier 1 evaluating an alert against standard baselines and auto-resolving without paging analysts:
```bash
python -m agentic_soc.cli simulate-fp
```

### Scenario B: Multi-Stage APT Attack with Strict Dual-Key Governance
Demonstrates Credential Stuffing $\rightarrow$ LSASS Memory Dump $\rightarrow$ C2 Beaconing $\rightarrow$ Lateral Pivot. High-impact containment actions (host isolation, account revocation) are paused pending human authorization:
```bash
python -m agentic_soc.cli simulate-apt
```

### Scenario C: Multi-Stage APT Attack with Human Authorization Granted
Simulates the human SOC lead granting dual-key approval, resulting in full SOAR containment and cryptographic audit logging:
```bash
python -m agentic_soc.cli simulate-apt --auto-approve-hitl --approver "Ken_Huang_SOC_Lead"
```

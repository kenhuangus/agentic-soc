"""Command-Line Interface (CLI) for Agentic AI SOC."""

import argparse
import sys
from .pipeline import SOCPipeline
from .scenarios.attack_chains import generate_false_positive_scenario, generate_apt_attack_chain
from .models.incident import AlertStatus


def run_false_positive() -> None:
    print("=" * 80)
    print("RUNNING SCENARIO A: FALSE POSITIVE ROUTINE ADMIN MAINTENANCE")
    print("=" * 80)
    finding, events, baseline_store = generate_false_positive_scenario()
    
    pipeline = SOCPipeline(baseline_store=baseline_store)
    pipeline.telemetry_bus.publish_batch(events)
    
    dossier = pipeline.process_incident(finding)
    
    print("\n--- INCIDENT DOSSIER RESULT ---")
    print(f"Incident ID   : {dossier.incident_id}")
    print(f"Status        : {dossier.status.value}")
    print(f"Anomaly Score : {dossier.anomaly_score}/1.0")
    print(f"Summary       : {dossier.summary}")
    print(f"Deviations    : {len(dossier.baseline_deviations)}")
    print("Decision      : AUTO-RESOLVED AT TIER 1 WITHOUT HUMAN INTERRUPTION.")
    print("=" * 80)


def run_apt_scenario(auto_approve: bool, approver: str) -> None:
    print("=" * 80)
    print("RUNNING SCENARIO B: MULTI-STAGE APT (LSASS DUMP -> C2 BEACON -> LATERAL PIVOT)")
    print(f"Dual-Key Mode : {'AUTO-APPROVED (HITL Granted)' if auto_approve else 'ENFORCE STRICT HITL GATE'}")
    print("=" * 80)
    
    finding, events, baseline_store = generate_apt_attack_chain()
    
    pipeline = SOCPipeline(baseline_store=baseline_store)
    pipeline.telemetry_bus.publish_batch(events)
    
    dossier = pipeline.process_incident(
        finding,
        human_approver=approver if auto_approve else None,
        auto_approve_hitl=auto_approve
    )
    
    print("\n[+] TIER 1: TRIAGE EVALUATION")
    print(f"    - Incident ID   : {dossier.incident_id}")
    print(f"    - Anomaly Score : {dossier.anomaly_score}/1.0")
    print(f"    - Baseline Deviations Detected ({len(dossier.baseline_deviations)}):")
    for dev in dossier.baseline_deviations:
        print(f"        * {dev}")

    print("\n[+] TIER 2: FORENSIC INVESTIGATION & ATTACK GRAPH")
    print(f"    - Blast Radius  : {dossier.blast_radius_score}/10.0")
    print(f"    - MITRE Tactics : {', '.join(dossier.mitre_techniques)}")
    print(f"    - Evidence Log  : {len(dossier.evidence_events)} OCSF events correlated")

    print("\n[+] TIER 3 & 4: CONTAINMENT ACTIONS & GOVERNANCE ENFORCEMENT")
    for idx, act in enumerate(dossier.containment_actions, 1):
        print(f"\n    Action #{idx}: {act.action_type.upper()} on {act.target_entity}")
        print(f"      - ID          : {act.action_id}")
        print(f"      - Severity    : {act.severity.value}")
        print(f"      - HITL Reqd   : {act.requires_hitl}")
        print(f"      - Approval    : {act.approval_status.value} (Approver: {act.approver})")
        print(f"      - Executed    : {act.executed}")
        print(f"      - Result      : {act.execution_result}")
        if act.audit_hash:
            print(f"      - Audit Hash  : {act.audit_hash}")

    print("\n" + "=" * 80)
    print(f"FINAL INCIDENT STATUS: {dossier.status.value}")
    print("=" * 80)


def main() -> None:
    parser = argparse.ArgumentParser(description="Agentic AI SOC Autonomous Security CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Subcommand: simulate-fp
    subparsers.add_parser("simulate-fp", help="Simulate a false positive event auto-resolved at Tier 1")

    # Subcommand: simulate-apt
    apt_parser = subparsers.add_parser("simulate-apt", help="Simulate a multi-stage APT attack chain through Tiers 1-4")
    apt_parser.add_argument("--auto-approve-hitl", action="store_true", help="Simulate granted human dual-key authorization")
    apt_parser.add_argument("--approver", default="Ken_Huang_SOC_Lead", help="Name of the human operator approver")

    args = parser.parse_args()

    if args.command == "simulate-fp":
        run_false_positive()
    elif args.command == "simulate-apt":
        run_apt_scenario(auto_approve=args.auto_approve_hitl, approver=args.approver)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

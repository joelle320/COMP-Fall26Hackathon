"""Measured held-out synthetic AccountWatch evaluation; no production claims."""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import statistics
import time

from .accountwatch import AccountWatch
from .store import Store
from .synthetic import generate_dataset


def ratio(numerator, denominator):
    return {"numerator": numerator, "denominator": denominator, "rate": numerator / denominator if denominator else None}


def evaluate_accountwatch():
    dataset = generate_dataset()
    with TemporaryDirectory(prefix="sentinel-accountwatch-evaluation-") as directory:
        service = AccountWatch(Store(Path(directory)))
        seeded = service.seed()
        before = {item["id"]: item for item in service.store.list("aw_baseline")}
        cases, latencies, alert_delays = [], [], []
        tp = fp = tn = fn = completed_reviews = 0
        benign_exceptions, expected_exceptions = 0, 0
        for case in dataset["evaluation"]:
            results = []
            for event in case["events"]:
                started = time.perf_counter()
                result = service.ingest(event)
                latencies.append((time.perf_counter() - started) * 1000)
                results.append(result)
                if result["anomaly"]:
                    alert_delays.append((datetime.fromisoformat(result["anomaly"]["alert_created_at"]) - datetime.fromisoformat(result["event"]["received_at"])).total_seconds() * 1000)
            detected = any(result["risk"]["score"] >= service.policy["review_score"] for result in results)
            labelled = case["label"] == "anomalous"
            tp += bool(labelled and detected)
            fp += bool(not labelled and detected)
            tn += bool(not labelled and not detected)
            fn += bool(labelled and not detected)
            if case["scenario"] in {"benign_after_hours", "benign_travel"}:
                benign_exceptions += 1
                expected_exceptions += not detected
            reviewed = 0
            for result in results:
                if result["anomaly"] and result["risk"]["score"] >= service.policy["review_score"]:
                    review = service.review(result["anomaly"]["id"], "close", "Synthetic fixture investigation completed by the evaluator.", "evaluation-analyst")
                    completed_reviews += review["status"] == "closed"
                    reviewed += 1
            cases.append({"id": case["id"], "ground_truth": case["label"], "scenario": case["scenario"], "detected_for_review": detected,
                          "max_risk_score": max(result["risk"]["score"] for result in results),
                          "reason_codes": sorted({reason["code"] for result in results for reason in result["risk"]["reasons"]}),
                          "reviewed_alerts": reviewed, "passed": labelled == detected})
        after = {item["id"]: item for item in service.store.list("aw_baseline")}
        alerts_for_review = sum(case["reviewed_alerts"] for case in cases)
        metrics = {"precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn), "false_positive_rate": ratio(fp, fp + tn),
                   "benign_exceptions_identified": ratio(expected_exceptions, benign_exceptions),
                   "analyst_review_completion": ratio(completed_reviews, alerts_for_review),
                   "median_detection_latency_ms": round(statistics.median(latencies), 3),
                   "median_event_to_alert_ms": round(statistics.median(alert_delays), 3) if alert_delays else None,
                   "unnecessary_review_interruptions": fp, "baseline_unchanged_after_evaluation": before == after}
        return {"generated_at": datetime.now(timezone.utc).isoformat(), "kind": "measured-held-out-synthetic-accountwatch",
                "dataset": {"employees": 20, "services": 3, "normal_training_samples": seeded["training_samples"],
                            "held_out_cases": len(cases), "normal_cases": tn + fp, "anomalous_cases": tp + fn,
                            "split": dataset["split"]},
                "confusion_matrix": {"true_positive": tp, "false_positive": fp, "true_negative": tn, "false_negative": fn},
                "metrics": metrics, "cases": cases, "audit_valid": service.store.verify()["valid"],
                "all_required_checks_passed": all(case["passed"] for case in cases) and before == after and service.store.verify()["valid"],
                "limitations": ["Small hand-labelled synthetic regression corpus, not real-world detection performance.",
                                "A review-priority score is not a compromise probability or a disciplinary recommendation.",
                                "Detection timing measures local ingest including persistence, on one host without load testing.",
                                "Event-to-alert time uses receipt-to-persisted-local-investigation timing, not historical event occurrence or corporate delivery.",
                                "Cross-module correlation accuracy and authorized agent completion are evaluated separately by enterprise tests/demo."]}

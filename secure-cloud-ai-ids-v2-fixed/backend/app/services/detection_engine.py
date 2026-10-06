from typing import Any, Dict, List
from app.models.entities import NetworkLog
from app.services.rule_engine import evaluate_network_rules
from app.services.ml_engine import ml_detector


def analyze_log(log: NetworkLog) -> List[Dict[str, Any]]:
    """Run deterministic rules and the ML anomaly detector, de-duplicating alerts."""
    results = evaluate_network_rules(log)
    ml_result = ml_detector.predict(log)
    if ml_result:
        results.append(ml_result)

    unique = {}
    for item in results:
        key = (item["alert_type"], item["summary"])
        unique[key] = item
    return list(unique.values())

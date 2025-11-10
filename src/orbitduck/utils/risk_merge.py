def merge_module_scores(nmap_score=0, shodan_score=0, spiderfoot_score=0, module_weights=None) -> float:
    """Combine module scores using weighted average."""
    if module_weights is None:
        module_weights = {"nmap": 0.4, "shodan": 0.3, "spiderfoot": 0.3}

    total_weight = sum(module_weights.values())
    if total_weight == 0:
        return 0.0

    weighted_sum = (
        (nmap_score * module_weights.get("nmap", 0)) +
        (shodan_score * module_weights.get("shodan", 0)) +
        (spiderfoot_score * module_weights.get("spiderfoot", 0))
    )

    return weighted_sum / total_weight

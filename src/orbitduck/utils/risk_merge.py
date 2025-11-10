# src/orbitduck/utils/risk_merge.py
def merge_risk_scores(*scores):
    """Combine multiple risk scores from different sources."""
    scores = [s for s in scores if s is not None]
    if not scores:
        return None
    # Weighted average example: give external data more influence
    weights = [1.0, 1.2, 1.5][:len(scores)]
    weighted = [s * w for s, w in zip(scores, weights)]
    return round(sum(weighted) / sum(weights), 2)

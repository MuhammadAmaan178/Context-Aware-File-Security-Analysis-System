import numpy as np

def detect_anomaly(current_size: int, history: list):
    """
    Lab 09: Z-Score Anomaly Detection.
    Returns: (bool, float) -> (is_anomaly, z_score)
    """
    if not history or len(history) < 2:
        return False, 0.0

    data = np.array(history)
    mean = np.mean(data)
    std_dev = np.std(data)

    if std_dev == 0:
        return False, 0.0

    z_score = (current_size - mean) / std_dev
    return abs(z_score) > 2.5, round(z_score, 2)

from synthetic_data.anomaly_detection import (
    train_model,
    predict,
    predict_one,
)

from synthetic_data.risk_engine import (
    assess_risk,
    assess_risks,
)

# Import however your project generates feature vectors
# Example:
#
# from synthetic_data.feature_engineering import build_feature_vectors
#
# feature_vectors = build_feature_vectors(...)
#
# OR load your existing feature_vectors list.

feature_vectors = ...   # <-- your generated FeatureVector list
Model artifacts removed — the old ones were trained on NSL-KDD and are no
longer compatible with this CIC-IoT-2023 version of the pipeline.

To regenerate them:
  1. Put the CIC-IoT-2023 CSV parts into the data/ folder (see data/README.md).
     Dataset: https://www.kaggle.com/datasets/himadri07/ciciot2023
     (or run: python download_dataset.py to fetch it automatically)
  2. pip install -r requirements.txt
  3. python train_ids_model.py

This regenerates:
  best_ids_model.pkl, feature_scaler.pkl, label_encoder.pkl, selected_features.pkl

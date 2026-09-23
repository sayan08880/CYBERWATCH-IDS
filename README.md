# Network IDS with Machine Learning

Real-time network intrusion detection system: a Flask web dashboard, a live
packet monitor (scapy), an ML prediction engine (scikit-learn), automatic
firewall IP blocking, batch CSV analysis, and CSV/PDF report export.

## What's in this package

| File                        | Purpose |
|-----------------------------|---------|
| `app.py`                    | Flask web app (dashboard, auth, reports, upload, admin, blocking) |
| `monitor.py`                | Live packet capture + rule-based detection + ML + auto-blocking |
| `live_prediction.py`        | Loads the trained model, predicts on single samples / CSV files |
| `packet_feature_extractor.py` | NSL-KDD style feature extraction from live packets |
| `blocking_service.py`       | Background service syncing firewall rules with the database |
| `requirements.txt`          | Dependencies (latest-version compatible ranges) |
| `run.bat` / `run.sh`        | One-click setup + start scripts |
| `commands.txt`              | Test attack commands (nmap/hping3) |

## What was fixed / modernized (vs. the old code)

1. **Registration crash** – `NameError: user_id` is fixed; new users are now
   logged in automatically after registering.
2. **Missing DB tables/columns** – `model_metrics` table and the
   `model_accuracy` / `model_f1_score` / `model_precision` /
   `review_status` columns are now created, with automatic migration for
   existing `ids_database.db` files.
3. **`netifaces` removed** – deprecated and fails to install on modern
   Python; gateway detection now uses scapy's built-in routing table.
4. **Monitor crash without model** – the packet handler no longer crashes
   when `models/` files are missing; it falls back to rule-based detection.
5. **Firewall rule names unified** – `IDS_Block_IN_<ip>` / `IDS_Block_OUT_<ip>`
   everywhere, so unblock actually removes the rules; `shell=True` removed.
6. **scikit-learn compatibility** – feature names are preserved through
   scaling (no more "X does not have valid feature names" errors on
   sklearn ≥ 1.6), and pickle version mismatches produce clear advice.
7. **Latest dependency versions** – open version ranges (Flask 3.1.x,
   pandas 2/3.x, NumPy 2.x, scikit-learn 1.5+…); see `requirements.txt`.
8. **PDF report export enabled** – `/download_report/pdf` now works
   (reportlab was installed but unused before).
9. Cleaner structure: duplicated imports/functions removed, debug spam
   moved behind `monitor.py --verbose`, English-only messages.

## Requirements

- **Python 3.11 – 3.14** (3.12+ recommended)
- **Windows:** install [Npcap](https://npcap.com) for packet capture
- **Admin/root rights** for live capture and firewall blocking

## Setup & run

### Option A – automatic

- **Windows:** right-click `run.bat` → *Run as administrator*
- **Linux/macOS:** `chmod +x run.sh && sudo ./run.sh`

### Option B – manual

```bash
python -m venv venv

# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

python app.py
```

Then open **http://localhost:5000** and log in with
**`admin` / `password123`** (created on first run).

## How the ML model fits into this project

```
Network Traffic → Feature Extraction → ML Model → Attack Detection → Alert/Block
```

| Stage | File | What it does |
|-------|------|---------------|
| Traffic capture | `monitor.py` | Sniffs live packets with scapy |
| Feature extraction | `packet_feature_extractor.py` | Turns raw packets into the 46 numeric flow features CIC-IoT-2023 uses |
| **ML training** | **`train_ids_model.py`** | Trains a `HistGradientBoostingClassifier` on the CIC-IoT-2023 dataset (`data/`) and saves the model to `models/` |
| **ML inference** | **`live_prediction.py`** | Loads the trained model and scores single samples / CSV batches |
| Detection + alert | `monitor.py`, `app.py` | Combines ML prediction with rule-based checks, raises an alert, logs it to `ids_database.db` |
| Block | `blocking_service.py` | Adds a firewall rule for IPs flagged as malicious |

**The model** is a `HistGradientBoostingClassifier` (scikit-learn) trained on
the CIC-IoT-2023 dataset's 46 flow-level features, classifying traffic into
8 classes: `Benign`, `DDoS`, `DoS`, `Mirai`, `Recon`, `Spoofing`, `Web`,
`BruteForce`. Features are standardized with a `StandardScaler` before
being fed to the model; a `LabelEncoder` maps between class names and the
model's numeric outputs. All four fitted objects
(`best_ids_model.pkl`, `feature_scaler.pkl`, `label_encoder.pkl`,
`selected_features.pkl`) are saved with `joblib` so `app.py` /
`live_prediction.py` / `monitor.py` can load them without retraining.

### Training the model yourself

1. Put CIC-IoT-2023 CSV files into the `data/` folder — see
   [`data/README.md`](data/README.md) for exact download steps
   (dataset: https://www.kaggle.com/datasets/himadri07/ciciot2023), or run:
   ```bash
   python download_dataset.py
   ```
2. Install dependencies and train:
   ```bash
   pip install -r requirements.txt
   python train_ids_model.py
   ```
   This reads every CSV in `data/`, trains the classifier, prints
   accuracy/F1/precision + a per-class report, and writes the 4 model files
   into `models/` (plus a `models/metrics.txt` summary).
3. Start the app — it will now auto-detect the model and enable
   *Live Prediction* / ML-based CSV analysis:
   ```bash
   python app.py
   ```

## Folders

`templates/` is fully included (dashboard, reports, uploads, users,
blocked IPs, live monitoring, etc. all render out of the box).

`data/` ships empty — that's where you put the CIC-IoT-2023 training CSVs
(see above). `models/` is where the trained model files end up after you
run `train_ids_model.py`:

```
network-ids-ml/
├── data/
│   └── (your CICIoT2023 part-*.csv files go here)
└── models/
    ├── best_ids_model.pkl
    ├── feature_scaler.pkl
    ├── label_encoder.pkl
    └── selected_features.pkl
```

Without the trained model files the app still runs fully - the Dashboard,
Reports, Upload (manual mode), Blocked IPs, and Admin pages all work with
zero ML files. Only *Live Prediction* and *auto/hybrid CSV analysis* need
the model.

> **Model version note:** if your `.pkl` files were saved with an old
> scikit-learn (e.g. 1.2.2), loading them under the latest version prints a
> warning. Usually they still work; if a load fails, either retrain/re-save
> the model or install the old version: `pip install "scikit-learn==1.2.2"`.

## Using the features

- **Dashboard / Reports / Upload / Access / Blocked IPs** – web UI, login first.
- **Live Monitoring** – open *Live Monitoring* in the UI and press Start, or
  run the monitor directly in an elevated terminal:
  ```bash
  python monitor.py            # all interfaces
  python monitor.py --iface "Wi-Fi" --verbose
  ```
- **Test detections** – run the commands from `commands.txt` from another
  machine/WSL against this host's IP.

## Configuration (environment variables)

| Variable         | Default              | Purpose |
|------------------|----------------------|---------|
| `IDS_SECRET_KEY` | `change-me-in-production` | Flask session secret – set a random value in production |
| `IDS_DB_PATH`    | `ids_database.db`    | SQLite database location |
| `IDS_UPLOAD_FOLDER` | `uploads`         | CSV upload folder |

## Notes & warnings

- Automatic firewall blocking needs **Administrator** (Windows) / **root**
  (Linux). Without it, IPs are still blocked at the application level.
- The default admin password is `password123` – **change it immediately**
  for anything beyond local testing.
- Only run the test attack commands on networks you own or are allowed to test.

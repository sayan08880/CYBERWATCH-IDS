# data/ — put the CICIoT2023 training CSVs here

This folder is where `train_ids_model.py` looks for the training data by
default. It ships empty (the dataset is ~501 MB, too big to bundle).

## 1. Get the dataset

You already have the Kaggle source:
https://www.kaggle.com/datasets/himadri07/ciciot2023

Two ways to download it:

### Option A — manual download (easiest)
1. Open the Kaggle link above → click **Download**.
2. Unzip it.
3. Copy the `.csv` part-files (e.g. `part-00001.csv`, `part-00002.csv`, ...)
   straight into this `data/` folder.

### Option B — Kaggle API (from a terminal)
```bash
pip install kaggle
# put your kaggle.json API token in ~/.kaggle/kaggle.json (Kaggle account settings)
kaggle datasets download -d himadri07/ciciot2023 -p data --unzip
```
Or simply run the helper script from the project root:
```bash
python download_dataset.py
```

## 2. Folder should look like this afterward

```
data/
├── README.md          (this file)
├── part-00001.csv
├── part-00002.csv
├── part-00003.csv
└── ... (as many parts as you want to train on)
```

You do **not** need all 169 official CIC-IoT-2023 CSV parts. For a
project/demo, **5–10 parts (a few hundred thousand rows)** is plenty and
trains in a few minutes on a laptop. More parts = better accuracy but
longer training time.

## 3. Train the model

From the project root:
```bash
python train_ids_model.py
```
By default it now automatically reads every `*.csv` file found in this
`data/` folder. You can also point it elsewhere:
```bash
python train_ids_model.py --data-dir /path/to/other/folder
python train_ids_model.py --files data/part-00001.csv data/part-00002.csv
```

This produces the 4 model files the app needs, saved into `models/`:
`best_ids_model.pkl`, `feature_scaler.pkl`, `label_encoder.pkl`,
`selected_features.pkl`.

> Note: raw CSV files are large — this folder has a `.gitignore` so they
> won't accidentally get committed to git.

"""
Download the CICIoT2023 dataset (Kaggle mirror) straight into data/.

Dataset: https://www.kaggle.com/datasets/himadri07/ciciot2023

Requirements:
    pip install kaggle
    Put your Kaggle API token at ~/.kaggle/kaggle.json
    (Kaggle -> Account -> Create New API Token -> downloads kaggle.json)

Usage:
    python download_dataset.py
"""

import os
import subprocess
import sys

DATASET = "himadri07/ciciot2023"


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(here, "data")
    os.makedirs(data_dir, exist_ok=True)

    try:
        import kaggle  # noqa: F401
    except ImportError:
        print("[*] 'kaggle' package not found, installing it...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "kaggle"])

    token_path = os.path.expanduser("~/.kaggle/kaggle.json")
    if not os.path.exists(token_path):
        raise SystemExit(
            "Kaggle API token not found at ~/.kaggle/kaggle.json.\n"
            "1. Go to https://www.kaggle.com/settings -> API -> 'Create New Token'\n"
            "2. Save the downloaded kaggle.json to ~/.kaggle/kaggle.json\n"
            "   (Windows: C:\\Users\\<you>\\.kaggle\\kaggle.json)\n"
            "3. Re-run this script.\n\n"
            "Or skip this script entirely and download the dataset manually from:\n"
            "https://www.kaggle.com/datasets/himadri07/ciciot2023\n"
            "then drop the CSV files into the data/ folder yourself."
        )

    print(f"[*] Downloading dataset '{DATASET}' into {data_dir} ...")
    subprocess.check_call([
        "kaggle", "datasets", "download",
        "-d", DATASET,
        "-p", data_dir,
        "--unzip",
    ])
    print(f"[OK] Dataset downloaded and extracted to {data_dir}/")
    print("Next step: python train_ids_model.py")


if __name__ == "__main__":
    main()

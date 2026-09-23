import argparse
import glob
import os
import time

import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.ensemble import (
    HistGradientBoostingClassifier,
    RandomForestClassifier
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)


# ==============================================================
# CIC-IoT-2023 FEATURES
# ==============================================================

RAW_COLUMNS = [
    "flow_duration",
    "Header_Length",
    "Protocol Type",
    "Duration",
    "Rate",
    "Srate",
    "Drate",
    "fin_flag_number",
    "syn_flag_number",
    "rst_flag_number",
    "psh_flag_number",
    "ack_flag_number",
    "ece_flag_number",
    "cwr_flag_number",
    "ack_count",
    "syn_count",
    "fin_count",
    "urg_count",
    "rst_count",
    "HTTP",
    "HTTPS",
    "DNS",
    "Telnet",
    "SMTP",
    "SSH",
    "IRC",
    "TCP",
    "UDP",
    "DHCP",
    "ARP",
    "ICMP",
    "IPv",
    "LLC",
    "Tot sum",
    "Min",
    "Max",
    "AVG",
    "Std",
    "Tot size",
    "IAT",
    "Number",
    "Magnitue",
    "Radius",
    "Covariance",
    "Variance",
    "Weight",
    "label",
]

SELECTED_FEATURES = [
    column for column in RAW_COLUMNS
    if column != "label"
]


# ==============================================================
# CIC-IoT-2023 ATTACK CATEGORY MAPPING
# ==============================================================

ATTACK_MAP = {

    # ----------------------------------------------------------
    # BENIGN
    # ----------------------------------------------------------

    "BenignTraffic": "Benign",

    # ----------------------------------------------------------
    # DDOS
    # ----------------------------------------------------------

    "DDoS-RSTFINFlood": "DDoS",
    "DDoS-PSHACK_Flood": "DDoS",
    "DDoS-SYN_Flood": "DDoS",
    "DDoS-UDP_Flood": "DDoS",
    "DDoS-TCP_Flood": "DDoS",
    "DDoS-ICMP_Flood": "DDoS",
    "DDoS-SynonymousIP_Flood": "DDoS",
    "DDoS-ACK_Fragmentation": "DDoS",
    "DDoS-UDP_Fragmentation": "DDoS",
    "DDoS-ICMP_Fragmentation": "DDoS",
    "DDoS-SlowLoris": "DDoS",
    "DDoS-HTTP_Flood": "DDoS",

    # ----------------------------------------------------------
    # DOS
    # ----------------------------------------------------------

    "DoS-UDP_Flood": "DoS",
    "DoS-SYN_Flood": "DoS",
    "DoS-TCP_Flood": "DoS",
    "DoS-HTTP_Flood": "DoS",

    # ----------------------------------------------------------
    # MIRAI
    # ----------------------------------------------------------

    "Mirai-greeth_flood": "Mirai",
    "Mirai-greip_flood": "Mirai",
    "Mirai-udpplain": "Mirai",

    # ----------------------------------------------------------
    # RECON
    # ----------------------------------------------------------

    "Recon-PingSweep": "Recon",
    "Recon-OSScan": "Recon",
    "Recon-PortScan": "Recon",
    "Recon-HostDiscovery": "Recon",
    "VulnerabilityScan": "Recon",

    # ----------------------------------------------------------
    # SPOOFING
    # ----------------------------------------------------------

    "DNS_Spoofing": "Spoofing",
    "MITM-ArpSpoofing": "Spoofing",

    # ----------------------------------------------------------
    # WEB
    # ----------------------------------------------------------

    "BrowserHijacking": "Web",
    "Backdoor_Malware": "Web",
    "XSS": "Web",
    "Uploading_Attack": "Web",
    "SqlInjection": "Web",
    "CommandInjection": "Web",

    # ----------------------------------------------------------
    # BRUTE FORCE
    # ----------------------------------------------------------

    "DictionaryBruteForce": "BruteForce",
}


# ==============================================================
# LOAD DATASET
# ==============================================================

def load_dataset(paths, max_rows_per_file=None):

    frames = []

    for path in paths:

        print(
            f"    Loading: {os.path.basename(path)}"
        )

        if max_rows_per_file is not None:

            df = pd.read_csv(
                path,
                nrows=max_rows_per_file
            )

        else:

            df = pd.read_csv(path)

        df.columns = [
            str(column).strip()
            for column in df.columns
        ]

        frames.append(df)

    if not frames:

        raise ValueError(
            "No CSV files were loaded."
        )

    df = pd.concat(
        frames,
        ignore_index=True
    )

    if "label" not in df.columns:

        raise ValueError(
            "The dataset does not contain a 'label' column."
        )

    df["label"] = (
        df["label"]
        .astype(str)
        .str.strip()
    )

    df["attack_category"] = (
        df["label"]
        .map(ATTACK_MAP)
        .fillna("Attack")
    )

    return df


# ==============================================================
# TRAINING FUNCTION
# ==============================================================

def train_and_evaluate(
    model_name,
    model,
    X_train,
    y_train,
    X_test,
    y_test,
    label_encoder
):

    print()
    print(
        f"[+] Training: {model_name}"
    )

    start_time = time.time()

    model.fit(
        X_train,
        y_train
    )

    training_time = (
        time.time() - start_time
    )

    print(
        f"    Training completed in "
        f"{training_time:.2f} seconds"
    )

    # ----------------------------------------------------------
    # PREDICTION
    # ----------------------------------------------------------

    prediction_start = time.time()

    y_pred = model.predict(
        X_test
    )

    prediction_time = (
        time.time() - prediction_start
    )

    # ----------------------------------------------------------
    # METRICS
    # ----------------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    precision = precision_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )

    macro_f1 = f1_score(
        y_test,
        y_pred,
        average="macro",
        zero_division=0
    )

    # ----------------------------------------------------------
    # PRINT RESULTS
    # ----------------------------------------------------------

    print()
    print(
        "    RESULTS"
    )
    print(
        "    " + "-" * 50
    )

    print(
        f"    Accuracy       : "
        f"{accuracy:.4f} "
        f"({accuracy * 100:.2f}%)"
    )

    print(
        f"    Precision      : "
        f"{precision:.4f}"
    )

    print(
        f"    Recall         : "
        f"{recall:.4f}"
    )

    print(
        f"    F1 Score       : "
        f"{f1:.4f}"
    )

    print(
        f"    Macro F1       : "
        f"{macro_f1:.4f}"
    )

    print(
        f"    Training Time  : "
        f"{training_time:.2f} sec"
    )

    print(
        f"    Prediction Time: "
        f"{prediction_time:.2f} sec"
    )

    # ----------------------------------------------------------
    # CLASSIFICATION REPORT
    # ----------------------------------------------------------

    print()
    print(
        "    Classification Report:"
    )

    print(
        classification_report(
            y_test,
            y_pred,
            target_names=label_encoder.classes_,
            zero_division=0
        )
    )

    result = {
        "Model": model_name,
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1 Score": f1,
        "Macro F1": macro_f1,
        "Training Time (sec)": training_time,
        "Prediction Time (sec)": prediction_time,
    }

    return model, result, y_pred


# ==============================================================
# PLOT: ACCURACY
# ==============================================================

def plot_accuracy(results_df, plots_dir):

    output_path = os.path.join(
        plots_dir,
        "accuracy_comparison.png"
    )

    best_index = results_df[
        "Accuracy"
    ].idxmax()

    best_model = results_df.loc[
        best_index,
        "Model"
    ]

    best_accuracy = results_df.loc[
        best_index,
        "Accuracy"
    ]

    plt.figure(
        figsize=(12, 7),
        dpi=150
    )

    bars = plt.bar(
        results_df["Model"],
        results_df["Accuracy"] * 100,
        width=0.60
    )

    # Highlight best model
    for index, bar in enumerate(bars):

        if results_df.iloc[index]["Model"] == best_model:

            bar.set_edgecolor("black")
            bar.set_linewidth(3)

        else:

            bar.set_alpha(0.65)

    # Accuracy labels
    for bar, value in zip(
        bars,
        results_df["Accuracy"] * 100
    ):

        plt.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.2,
            f"{value:.2f}%",
            ha="center",
            va="bottom",
            fontsize=11,
            fontweight="bold"
        )

    plt.title(
        "CIC-IoT-2023 Machine Learning Accuracy Comparison",
        fontsize=17,
        fontweight="bold",
        pad=15
    )

    plt.xlabel(
        "Machine Learning Algorithm",
        fontsize=12
    )

    plt.ylabel(
        "Accuracy (%)",
        fontsize=12
    )

    plt.ylim(
        max(
            0,
            results_df["Accuracy"].min() * 100 - 5
        ),
        101
    )

    plt.grid(
        axis="y",
        linestyle="--",
        alpha=0.3
    )

    plt.xticks(
        rotation=15
    )

    plt.tight_layout()

    plt.savefig(
        output_path,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(
        f"[OK] Accuracy plot saved: "
        f"{output_path}"
    )


# ==============================================================
# PLOT: ALL METRICS
# ==============================================================

def plot_all_metrics(results_df, plots_dir):

    output_path = os.path.join(
        plots_dir,
        "model_metrics_comparison.png"
    )

    x = np.arange(
        len(results_df)
    )

    width = 0.20

    plt.figure(
        figsize=(14, 8),
        dpi=150
    )

    plt.bar(
        x - (width * 1.5),
        results_df["Accuracy"] * 100,
        width,
        label="Accuracy"
    )

    plt.bar(
        x - (width * 0.5),
        results_df["Precision"] * 100,
        width,
        label="Precision"
    )

    plt.bar(
        x + (width * 0.5),
        results_df["Recall"] * 100,
        width,
        label="Recall"
    )

    plt.bar(
        x + (width * 1.5),
        results_df["F1 Score"] * 100,
        width,
        label="F1 Score"
    )

    plt.title(
        "CIC-IoT-2023 Model Performance Comparison",
        fontsize=17,
        fontweight="bold",
        pad=15
    )

    plt.xlabel(
        "Machine Learning Algorithm",
        fontsize=12
    )

    plt.ylabel(
        "Score (%)",
        fontsize=12
    )

    plt.xticks(
        x,
        results_df["Model"],
        rotation=15
    )

    plt.ylim(
        max(
            0,
            results_df[
                [
                    "Accuracy",
                    "Precision",
                    "Recall",
                    "F1 Score"
                ]
            ].min().min() * 100 - 5
        ),
        101
    )

    plt.grid(
        axis="y",
        linestyle="--",
        alpha=0.3
    )

    plt.legend(
        fontsize=10
    )

    plt.tight_layout()

    plt.savefig(
        output_path,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(
        f"[OK] Metrics plot saved: "
        f"{output_path}"
    )


# ==============================================================
# PLOT: TRAINING TIME
# ==============================================================

def plot_training_time(results_df, plots_dir):

    output_path = os.path.join(
        plots_dir,
        "training_time_comparison.png"
    )

    plt.figure(
        figsize=(12, 7),
        dpi=150
    )

    bars = plt.bar(
        results_df["Model"],
        results_df["Training Time (sec)"],
        width=0.60
    )

    for bar, value in zip(
        bars,
        results_df["Training Time (sec)"]
    ):

        plt.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{value:.2f}s",
            ha="center",
            va="bottom",
            fontsize=10
        )

    plt.title(
        "Machine Learning Training Time Comparison",
        fontsize=17,
        fontweight="bold",
        pad=15
    )

    plt.xlabel(
        "Machine Learning Algorithm",
        fontsize=12
    )

    plt.ylabel(
        "Training Time (seconds)",
        fontsize=12
    )

    plt.grid(
        axis="y",
        linestyle="--",
        alpha=0.3
    )

    plt.xticks(
        rotation=15
    )

    plt.tight_layout()

    plt.savefig(
        output_path,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(
        f"[OK] Training-time plot saved: "
        f"{output_path}"
    )


# ==============================================================
# PLOT: CONFUSION MATRIX
# ==============================================================

def plot_confusion_matrix(
    model_name,
    y_test,
    y_pred,
    label_encoder,
    plots_dir
):

    safe_name = (
        model_name
        .lower()
        .replace(" ", "_")
    )

    output_path = os.path.join(
        plots_dir,
        f"confusion_matrix_{safe_name}.png"
    )

    cm = confusion_matrix(
        y_test,
        y_pred
    )

    fig, ax = plt.subplots(
        figsize=(11, 9),
        dpi=150
    )

    display = ConfusionMatrixDisplay(
        confusion_matrix=cm,
        display_labels=label_encoder.classes_
    )

    display.plot(
        ax=ax,
        xticks_rotation=45,
        cmap="Blues",
        colorbar=True
    )

    ax.set_title(
        f"Confusion Matrix - {model_name}",
        fontsize=16,
        fontweight="bold",
        pad=15
    )

    plt.tight_layout()

    plt.savefig(
        output_path,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(
        f"[OK] Confusion matrix saved: "
        f"{output_path}"
    )


# ==============================================================
# MAIN
# ==============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "CIC-IoT-2023 Multi-Algorithm "
            "Network Intrusion Detection System"
        )
    )

    parser.add_argument(
        "--data-dir",
        type=str,
        default=None,
        help="Directory containing CIC-IoT-2023 CSV files"
    )

    parser.add_argument(
        "--files",
        nargs="*",
        default=None,
        help="Explicit CSV files"
    )

    parser.add_argument(
        "--max-rows-per-file",
        type=int,
        default=200000,
        help=(
            "Maximum rows to read from each CSV. "
            "Use 0 for all rows."
        )
    )

    parser.add_argument(
        "--svm-samples",
        type=int,
        default=20000,
        help=(
            "Number of stratified training samples "
            "used by SVM. Default: 20000"
        )
    )

    args = parser.parse_args()

    # ==========================================================
    # DIRECTORIES
    # ==========================================================

    here = os.path.dirname(
        os.path.abspath(__file__)
    )

    data_dir = os.path.join(
        here,
        "data"
    )

    models_dir = os.path.join(
        here,
        "models"
    )

    plots_dir = os.path.join(
        here,
        "plots"
    )

    os.makedirs(
        models_dir,
        exist_ok=True
    )

    os.makedirs(
        plots_dir,
        exist_ok=True
    )

    # ==========================================================
    # FIND DATASET FILES
    # ==========================================================

    if args.files:

        csv_paths = args.files

    elif args.data_dir:

        csv_paths = sorted(
            glob.glob(
                os.path.join(
                    args.data_dir,
                    "*.csv"
                )
            )
        )

    else:

        csv_paths = sorted(
            glob.glob(
                os.path.join(
                    data_dir,
                    "*.csv"
                )
            )
        )

    if not csv_paths:

        raise SystemExit(
            f"""
No CSV files found.

Expected directory:

{data_dir}

Put your CIC-IoT-2023 CSV files there.

Or use:

python Train_IDS_MODEL.py --data-dir /path/to/dataset
"""
        )

    # ==========================================================
    # HEADER
    # ==========================================================

    print()
    print("=" * 70)
    print(" CIC-IoT-2023 NETWORK INTRUSION DETECTION")
    print(" MULTI-ALGORITHM MACHINE LEARNING TRAINING")
    print("=" * 70)

    print(
        f"\n[*] Found {len(csv_paths)} CSV file(s)"
    )

    # ==========================================================
    # LOAD DATA
    # ==========================================================

    print(
        "\n[*] Loading dataset..."
    )

    max_rows = (
        None
        if args.max_rows_per_file <= 0
        else args.max_rows_per_file
    )

    df = load_dataset(
        csv_paths,
        max_rows
    )

    print(
        f"\n[OK] Loaded {len(df):,} rows"
    )

    # ==========================================================
    # CLASS DISTRIBUTION
    # ==========================================================

    print()
    print("=" * 70)
    print(" CLASS DISTRIBUTION")
    print("=" * 70)

    print(
        df["attack_category"]
        .value_counts()
        .to_string()
    )

    # ==========================================================
    # CHECK FEATURES
    # ==========================================================

    print(
        "\n[*] Preparing features..."
    )

    missing_columns = [
        column
        for column in SELECTED_FEATURES
        if column not in df.columns
    ]

    if missing_columns:

        raise ValueError(
            "Missing required feature columns:\n"
            + "\n".join(missing_columns)
        )

    X = df[
        SELECTED_FEATURES
    ].apply(
        pd.to_numeric,
        errors="coerce"
    )

    X = X.replace(
        [np.inf, -np.inf],
        0
    )

    X = X.fillna(0)

    y_raw = df[
        "attack_category"
    ]

    # ==========================================================
    # LABEL ENCODING
    # ==========================================================

    label_encoder = LabelEncoder()

    y = label_encoder.fit_transform(
        y_raw
    )

    print(
        "\n[*] Classes:"
    )

    for number, name in enumerate(
        label_encoder.classes_
    ):

        print(
            f"    {number}: {name}"
        )

    # ==========================================================
    # TRAIN / TEST SPLIT
    # ==========================================================

    print(
        "\n[*] Splitting dataset..."
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print(
        f"[OK] Training samples: "
        f"{len(X_train):,}"
    )

    print(
        f"[OK] Testing samples : "
        f"{len(X_test):,}"
    )

    # ==========================================================
    # STANDARD SCALER
    # ==========================================================

    print(
        "\n[*] Applying StandardScaler..."
    )

    scaler = StandardScaler()

    X_train_scaled = scaler.fit_transform(
        X_train
    )

    X_test_scaled = scaler.transform(
        X_test
    )

    print(
        "[OK] Feature scaling completed"
    )

    # ==========================================================
    # RESULTS STORAGE
    # ==========================================================

    results = []

    trained_models = {}

    predictions = {}

    # ==========================================================
    # 1. HIST GRADIENT BOOSTING
    # ==========================================================

    hgb_model = HistGradientBoostingClassifier(
        random_state=42
    )

    hgb_model, result, prediction = train_and_evaluate(
        "HistGradientBoosting",
        hgb_model,
        X_train_scaled,
        y_train,
        X_test_scaled,
        y_test,
        label_encoder
    )

    results.append(result)

    trained_models[
        "HistGradientBoosting"
    ] = hgb_model

    predictions[
        "HistGradientBoosting"
    ] = prediction

    # ==========================================================
    # 2. RANDOM FOREST
    # ==========================================================

    rf_model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
        max_features="sqrt"
    )

    rf_model, result, prediction = train_and_evaluate(
        "Random Forest",
        rf_model,
        X_train_scaled,
        y_train,
        X_test_scaled,
        y_test,
        label_encoder
    )

    results.append(result)

    trained_models[
        "Random Forest"
    ] = rf_model

    predictions[
        "Random Forest"
    ] = prediction

    # ==========================================================
    # 3. KNN
    # ==========================================================

    knn_model = KNeighborsClassifier(
        n_neighbors=5,
        n_jobs=-1
    )

    knn_model, result, prediction = train_and_evaluate(
        "KNN",
        knn_model,
        X_train_scaled,
        y_train,
        X_test_scaled,
        y_test,
        label_encoder
    )

    results.append(result)

    trained_models[
        "KNN"
    ] = knn_model

    predictions[
        "KNN"
    ] = prediction

    # ==========================================================
    # 4. SVM
    # ==========================================================

    print()
    print(
        "[+] Preparing SVM training subset..."
    )

    svm_sample_count = min(
        args.svm_samples,
        len(X_train_scaled)
    )

    if svm_sample_count < len(X_train_scaled):

        print(
            f"    Full training samples : "
            f"{len(X_train_scaled):,}"
        )

        print(
            f"    SVM training samples  : "
            f"{svm_sample_count:,}"
        )

        print(
            "    Using stratified sampling..."
        )

        X_svm, _, y_svm, _ = train_test_split(
            X_train_scaled,
            y_train,
            train_size=svm_sample_count,
            random_state=42,
            stratify=y_train
        )

    else:

        X_svm = X_train_scaled
        y_svm = y_train

    svm_model = SVC(
        kernel="rbf",
        C=10,
        gamma="scale",
        cache_size=4096,
        class_weight="balanced"
    )

    svm_model, result, prediction = train_and_evaluate(
        "SVM",
        svm_model,
        X_svm,
        y_svm,
        X_test_scaled,
        y_test,
        label_encoder
    )

    results.append(result)

    trained_models[
        "SVM"
    ] = svm_model

    predictions[
        "SVM"
    ] = prediction

    # ==========================================================
    # RESULTS DATAFRAME
    # ==========================================================

    results_df = pd.DataFrame(
        results
    )

    results_df = results_df.sort_values(
        by="Accuracy",
        ascending=False
    ).reset_index(
        drop=True
    )

    # ==========================================================
    # FINAL COMPARISON
    # ==========================================================

    print()
    print("=" * 70)
    print(" FINAL MODEL COMPARISON")
    print("=" * 70)

    print()

    for _, row in results_df.iterrows():

        print(
            f"{row['Model']}"
        )

        print(
            f"    Accuracy  : "
            f"{row['Accuracy']:.4f} "
            f"({row['Accuracy'] * 100:.2f}%)"
        )

        print(
            f"    Precision : "
            f"{row['Precision']:.4f}"
        )

        print(
            f"    Recall    : "
            f"{row['Recall']:.4f}"
        )

        print(
            f"    F1 Score  : "
            f"{row['F1 Score']:.4f}"
        )

        print(
            f"    Macro F1  : "
            f"{row['Macro F1']:.4f}"
        )

        print(
            f"    Train Time: "
            f"{row['Training Time (sec)']:.2f} sec"
        )

        print()

    # ==========================================================
    # BEST MODEL
    # ==========================================================

    best_model_name = results_df.iloc[0][
        "Model"
    ]

    best_accuracy = results_df.iloc[0][
        "Accuracy"
    ]

    best_model = trained_models[
        best_model_name
    ]

    print("=" * 70)
    print(" BEST ACCURACY MODEL")
    print("=" * 70)

    print(
        f"\nModel    : {best_model_name}"
    )

    print(
        f"Accuracy : "
        f"{best_accuracy:.4f} "
        f"({best_accuracy * 100:.2f}%)"
    )

    # ==========================================================
    # SAVE MODEL COMPARISON CSV
    # ==========================================================

    comparison_csv = os.path.join(
        models_dir,
        "model_comparison.csv"
    )

    results_df.to_csv(
        comparison_csv,
        index=False
    )

    print(
        f"\n[OK] Model comparison saved:"
        f"\n     {comparison_csv}"
    )

    # ==========================================================
    # SAVE BEST MODEL
    # ==========================================================

    best_model_path = os.path.join(
        models_dir,
        "best_ids_model.pkl"
    )

    joblib.dump(
        best_model,
        best_model_path
    )

    print(
        f"[OK] Best model saved:"
        f"\n     {best_model_path}"
    )

    # ==========================================================
    # SAVE SCALER
    # ==========================================================

    scaler_path = os.path.join(
        models_dir,
        "feature_scaler.pkl"
    )

    joblib.dump(
        scaler,
        scaler_path
    )

    print(
        f"[OK] Scaler saved:"
        f"\n     {scaler_path}"
    )

    # ==========================================================
    # SAVE LABEL ENCODER
    # ==========================================================

    encoder_path = os.path.join(
        models_dir,
        "label_encoder.pkl"
    )

    joblib.dump(
        label_encoder,
        encoder_path
    )

    print(
        f"[OK] Label encoder saved:"
        f"\n     {encoder_path}"
    )

    # ==========================================================
    # SAVE FEATURES
    # ==========================================================

    features_path = os.path.join(
        models_dir,
        "selected_features.pkl"
    )

    joblib.dump(
        SELECTED_FEATURES,
        features_path
    )

    print(
        f"[OK] Selected features saved:"
        f"\n     {features_path}"
    )

    # ==========================================================
    # SAVE ALL MODELS
    # ==========================================================

    all_models_path = os.path.join(
        models_dir,
        "all_models.pkl"
    )

    joblib.dump(
        trained_models,
        all_models_path
    )

    print(
        f"[OK] All models saved:"
        f"\n     {all_models_path}"
    )

    # ==========================================================
    # SAVE METRICS TEXT
    # ==========================================================

    metrics_path = os.path.join(
        models_dir,
        "metrics.txt"
    )

    with open(
        metrics_path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "CIC-IoT-2023 MACHINE LEARNING MODEL COMPARISON\n"
        )

        file.write(
            "=" * 70 + "\n\n"
        )

        file.write(
            f"Dataset rows used: "
            f"{len(df):,}\n"
        )

        file.write(
            f"Training samples: "
            f"{len(X_train):,}\n"
        )

        file.write(
            f"Testing samples: "
            f"{len(X_test):,}\n"
        )

        file.write(
            f"SVM training samples: "
            f"{len(X_svm):,}\n\n"
        )

        file.write(
            "MODEL PERFORMANCE\n"
        )

        file.write(
            "=" * 70 + "\n\n"
        )

        for _, row in results_df.iterrows():

            file.write(
                f"Model: {row['Model']}\n"
            )

            file.write(
                f"Accuracy: "
                f"{row['Accuracy']:.4f}\n"
            )

            file.write(
                f"Precision: "
                f"{row['Precision']:.4f}\n"
            )

            file.write(
                f"Recall: "
                f"{row['Recall']:.4f}\n"
            )

            file.write(
                f"F1 Score: "
                f"{row['F1 Score']:.4f}\n"
            )

            file.write(
                f"Macro F1: "
                f"{row['Macro F1']:.4f}\n"
            )

            file.write(
                f"Training Time: "
                f"{row['Training Time (sec)']:.2f} sec\n"
            )

            file.write(
                f"Prediction Time: "
                f"{row['Prediction Time (sec)']:.2f} sec\n\n"
            )

        file.write(
            "=" * 70 + "\n"
        )

        file.write(
            f"Best Accuracy Model: "
            f"{best_model_name}\n"
        )

        file.write(
            f"Best Accuracy: "
            f"{best_accuracy:.4f} "
            f"({best_accuracy * 100:.2f}%)\n"
        )

        file.write(
            "=" * 70 + "\n"
        )

    print(
        f"[OK] Metrics saved:"
        f"\n     {metrics_path}"
    )

    # ==========================================================
    # GENERATE PLOTS
    # ==========================================================

    print()
    print("=" * 70)
    print(" GENERATING HIGH-QUALITY PLOTS")
    print("=" * 70)

    # Accuracy comparison
    plot_accuracy(
        results_df,
        plots_dir
    )

    # Accuracy / Precision / Recall / F1
    plot_all_metrics(
        results_df,
        plots_dir
    )

    # Training time
    plot_training_time(
        results_df,
        plots_dir
    )

    # ==========================================================
    # CONFUSION MATRICES
    # ==========================================================

    print(
        "\n[*] Generating confusion matrices..."
    )

    for model_name in predictions:

        plot_confusion_matrix(
            model_name,
            y_test,
            predictions[model_name],
            label_encoder,
            plots_dir
        )

    # ==========================================================
    # FINAL
    # ==========================================================

    print()
    print("=" * 70)
    print(" TRAINING COMPLETED SUCCESSFULLY")
    print("=" * 70)

    print(
        f"""
Best accuracy model:
    {best_model_name}

Best accuracy:
    {best_accuracy * 100:.2f}%

Saved model:
    models/best_ids_model.pkl

Model comparison:
    models/model_comparison.csv

Metrics:
    models/metrics.txt

All models:
    models/all_models.pkl

Plots:
    plots/accuracy_comparison.png
    plots/model_metrics_comparison.png
    plots/training_time_comparison.png

Confusion matrices:
    plots/confusion_matrix_histgradientboosting.png
    plots/confusion_matrix_random_forest.png
    plots/confusion_matrix_knn.png
    plots/confusion_matrix_svm.png
"""
    )


# ==============================================================
# PROGRAM ENTRY POINT
# ==============================================================

if __name__ == "__main__":
    main()
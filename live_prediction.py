"""
Live IDS Prediction System
===========================
Loads a trained scikit-learn model (+ scaler, label encoder, feature list)
and produces predictions for single samples or whole CSV files.

Modernizations:
- Keeps feature names attached through scaling so scikit-learn >= 1.2 does
  not raise "X does not have valid feature names" warnings/errors.
- Detects pickle/sklearn version mismatches and prints actionable advice.
- Works with NumPy 2.x and pandas 2.x / 3.x.
"""

import glob
import os
import warnings

import joblib
import numpy as np
import pandas as pd


class LiveIDSPredictor:
    def __init__(self, model_path="models/best_ids_model.pkl"):
        """
        Args:
            model_path: Path to the saved best model (.pkl / .joblib)
        """
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names = None
        self.is_loaded = False

        # Expected CIC-IoT-2023 style feature names (fallback if not saved)
        self.expected_features = [
            "flow_duration", "Header_Length", "Protocol Type", "Duration", "Rate",
            "Srate", "Drate", "fin_flag_number", "syn_flag_number", "rst_flag_number",
            "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number",
            "ack_count", "syn_count", "fin_count", "urg_count", "rst_count",
            "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP",
            "DHCP", "ARP", "ICMP", "IPv", "LLC", "Tot sum", "Min", "Max", "AVG",
            "Std", "Tot size", "IAT", "Number", "Magnitue", "Radius", "Covariance",
            "Variance", "Weight",
        ]

        self.load_model_components()

    # ------------------------------------------------------------------
    @staticmethod
    def _safe_joblib_load(path, description):
        """Load a joblib artifact with a clear message on version mismatch."""
        try:
            with warnings.catch_warnings():
                # Surface the sklearn version warning but don't crash on it
                warnings.simplefilter("always")
                return joblib.load(path)
        except Exception as e:
            print(f"[WARN] Could not load {description} from {path}: {e}")
            print("       This usually means the file was saved with an older")
            print("       scikit-learn. Re-save/retrain it with your installed")
            print("       version, or install the version it was trained with.")
            return None

    def load_model_components(self):
        """Load all model components saved during training."""
        try:
            print("[*] Loading model components...")

            if os.path.exists(self.model_path):
                self.model = self._safe_joblib_load(self.model_path, "model")
                if self.model is None:
                    self.is_loaded = False
                    return
                print(f"[OK] Model loaded: {type(self.model).__name__}")
            else:
                raise FileNotFoundError(f"Model file not found: {self.model_path}")

            scaler_path = os.path.join("models", "feature_scaler.pkl")
            if os.path.exists(scaler_path):
                self.scaler = self._safe_joblib_load(scaler_path, "feature scaler")
                if self.scaler is not None:
                    print("[OK] Loaded feature scaler")
            else:
                print("[WARN] Scaler not found, scaling will be skipped")

            encoder_path = os.path.join("models", "label_encoder.pkl")
            if os.path.exists(encoder_path):
                self.label_encoder = self._safe_joblib_load(encoder_path, "label encoder")
                if self.label_encoder is not None:
                    print("[OK] Label encoder loaded")
                    print(f"     Attack categories: {list(self.label_encoder.classes_)}")
            else:
                print("[WARN] Label encoder not found")

            features_path = os.path.join("models", "selected_features.pkl")
            if os.path.exists(features_path):
                self.feature_names = self._safe_joblib_load(features_path, "feature list")
                if self.feature_names is not None:
                    print(f"[OK] Loaded feature names: {len(self.feature_names)} features")
                else:
                    self.feature_names = self.expected_features
            else:
                self.feature_names = self.expected_features
                print("[WARN] Using default feature names")

            self.is_loaded = True
            print("[*] Model system ready for predictions!")

        except Exception as e:
            print(f"[ERROR] Loading model components: {e}")
            self.is_loaded = False

    # ------------------------------------------------------------------
    def preprocess_data(self, data):
        """
        Preprocess input data to match the training format.

        Returns:
            (scaled_df, clean_df) - both pandas DataFrames WITH column names
            so modern scikit-learn feature-name validation stays happy.
        """
        processed_data = data.copy()

        # Fill any missing features with 0
        missing_features = [f for f in self.feature_names
                            if f not in processed_data.columns]
        for feature in missing_features:
            processed_data[feature] = 0
        if missing_features:
            print(f"[WARN] Missing features filled with 0: {missing_features}")

        # Select only the features used in training, in the right order
        processed_data = processed_data[self.feature_names]

        # Clean up (same as training)
        processed_data = (
            processed_data.fillna(0)
            .replace([np.inf, -np.inf], 0)
            .apply(lambda col: pd.to_numeric(col, errors="coerce").fillna(0))
        )

        if self.scaler is not None:
            scaled = self.scaler.transform(processed_data)
            # Keep feature names attached (sklearn >= 1.2 checks them)
            processed_data_scaled = pd.DataFrame(
                scaled, columns=self.feature_names, index=processed_data.index
            )
        else:
            processed_data_scaled = processed_data

        return processed_data_scaled, processed_data

    # ------------------------------------------------------------------
    def predict_single_sample(self, features_dict):
        """
        Predict the attack category for a single sample.

        Returns:
            (predicted_category, confidence, probabilities)
        """
        if not self.is_loaded:
            return "Model not loaded", 0.0, None

        sample_df = pd.DataFrame([features_dict])
        processed_data, _ = self.preprocess_data(sample_df)

        prediction = self.model.predict(processed_data)

        probabilities = None
        confidence = 1.0
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(processed_data)[0]
            confidence = float(np.max(probabilities))

        if self.label_encoder is not None:
            predicted_category = self.label_encoder.inverse_transform(prediction)[0]
        else:
            predicted_category = prediction[0]

        return predicted_category, confidence, probabilities

    # ------------------------------------------------------------------
    def predict_from_csv(self, csv_file_path, save_results=True):
        """Predict attack categories for every row of a CSV file."""
        if not self.is_loaded:
            print("[ERROR] Model not loaded properly")
            return None

        try:
            print(f"[*] Loading data from: {csv_file_path}")
            data = pd.read_csv(csv_file_path)
            print(f"[OK] Loaded {len(data)} samples with {len(data.columns)} columns")

            processed_data, _ = self.preprocess_data(data)

            print("[*] Making predictions...")
            predictions = self.model.predict(processed_data)

            probabilities = confidences = None
            if hasattr(self.model, "predict_proba"):
                probabilities = self.model.predict_proba(processed_data)
                confidences = np.max(probabilities, axis=1)

            if self.label_encoder is not None:
                predicted_categories = self.label_encoder.inverse_transform(predictions)
            else:
                predicted_categories = predictions

            results_df = data.copy()
            results_df["predicted_attack_category"] = predicted_categories
            if confidences is not None:
                results_df["prediction_confidence"] = confidences
            if probabilities is not None and self.label_encoder is not None:
                for i, category in enumerate(self.label_encoder.classes_):
                    results_df[f'prob_{str(category).replace(" ", "_")}'] = probabilities[:, i]

            # ---- Summary ----
            category_counts = pd.Series(predicted_categories).value_counts()
            print("\n" + "=" * 60)
            print("PREDICTION RESULTS SUMMARY")
            print("=" * 60)
            print(f"Total samples processed : {len(data)}")
            if confidences is not None:
                print(f"Average confidence      : {np.mean(confidences):.3f}")
                print(f"Confidence range        : "
                      f"{np.min(confidences):.3f} - {np.max(confidences):.3f}")
            print("\nAttack Category Distribution:")
            for category, count in category_counts.items():
                print(f"   {category:<30}: {count:>6} ({count / len(data) * 100:>5.1f}%)")

            normal_count = int(category_counts.get("Normal", 0))
            attack_count = len(data) - normal_count
            threat_percentage = attack_count / len(data) * 100

            print("\nThreat Assessment:")
            print(f"   Normal traffic: {normal_count} ({100 - threat_percentage:.1f}%)")
            print(f"   Attack traffic: {attack_count} ({threat_percentage:.1f}%)")

            if threat_percentage > 50:
                threat_level = "HIGH THREAT"
            elif threat_percentage > 20:
                threat_level = "MEDIUM THREAT"
            elif threat_percentage > 5:
                threat_level = "LOW THREAT"
            else:
                threat_level = "MINIMAL THREAT"
            print(f"   Threat Level: {threat_level}")

            if save_results:
                output_file = csv_file_path.replace(".csv", "_predictions.csv")
                results_df.to_csv(output_file, index=False)
                print(f"\nResults saved to: {output_file}")

                summary_file = csv_file_path.replace(".csv", "_summary.csv")
                pd.DataFrame({
                    "attack_category": category_counts.index,
                    "count": category_counts.values,
                    "percentage": (category_counts.values / len(data) * 100).round(2),
                }).to_csv(summary_file, index=False)
                print(f"Summary saved to: {summary_file}")

            return results_df

        except Exception as e:
            print(f"[ERROR] During prediction: {e}")
            return None

    # ------------------------------------------------------------------
    def batch_predict_directory(self, directory_path, file_pattern="*.csv"):
        """Predict for all CSV files in a directory."""
        if not self.is_loaded:
            print("[ERROR] Model not loaded properly")
            return None

        csv_files = glob.glob(os.path.join(directory_path, file_pattern))
        if not csv_files:
            print(f"[ERROR] No CSV files found in {directory_path}")
            return None

        print(f"[*] Found {len(csv_files)} CSV files to process")
        results = {}
        for i, csv_file in enumerate(csv_files, 1):
            print(f"\n{'=' * 60}")
            print(f"Processing file {i}/{len(csv_files)}: {os.path.basename(csv_file)}")
            print("=" * 60)
            results[csv_file] = self.predict_from_csv(csv_file, save_results=True)

        print(f"\n[OK] Batch prediction completed for {len(csv_files)} files")
        return results


# ----------------------------------------------------------------------
# Simple usage helpers
# ----------------------------------------------------------------------
def predict_from_file(csv_file_path, model_path="models/best_ids_model.pkl"):
    predictor = LiveIDSPredictor(model_path)
    return predictor.predict_from_csv(csv_file_path)


def predict_single(features_dict, model_path="models/best_ids_model.pkl"):
    predictor = LiveIDSPredictor(model_path)
    category, confidence, _ = predictor.predict_single_sample(features_dict)
    return category, confidence

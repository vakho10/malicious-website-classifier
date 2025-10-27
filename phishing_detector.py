import warnings

warnings.filterwarnings("ignore", category=UserWarning)

import pandas as pd
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from ucimlrepo import fetch_ucirepo
import joblib

from feature_extractor import FeatureExtractor
from config import *


class PhishingDetector:
    """Neural network-based phishing detection system"""

    def __init__(self, model=None, scaler=None):
        self.model = model
        self.scaler = scaler

    @classmethod
    def load(cls, model_path=MODEL_PATH, scaler_path=SCALER_PATH):
        """Load saved model and scaler"""
        print(f"Loading model from {model_path}...")
        model = tf.keras.models.load_model(model_path)
        scaler = joblib.load(scaler_path)
        return cls(model, scaler)

    def train(self, test_size=TEST_SIZE, epochs=EPOCHS, batch_size=BATCH_SIZE):
        """Train model on UCI dataset (id=379)"""
        # Load dataset
        print("Loading UCI Website Phishing dataset (id=379)...")
        data = fetch_ucirepo(id=379)
        X, y = data.data.features, data.data.targets.iloc[:, 0].astype(int)

        # Map labels to binary: 0=legit, 1=phish
        print(f"Original labels: {sorted(y.unique())}")
        unique_labels = set(y.unique())

        # CRITICAL: UCI dataset id=379 has REVERSED semantics!
        # In this dataset: -1 = LEGITIMATE, 0/1 = PHISHING
        # This is confirmed by feature analysis (legit sites have bad features)

        if unique_labels == {-1, 1}:
            # Standard reversed encoding: -1=legit, 1=phish
            y = y.map({-1: 0, 1: 1})
        elif -1 in unique_labels:
            # Has -1 (legitimate) with others (phishing)
            # Map: -1 → 0 (legit), everything else → 1 (phish)
            y = (y != -1).astype(int)
        elif unique_labels == {0, 1}:
            # Already binary - keep as is
            print("Labels already 0/1 - keeping as is")
        else:
            # Fallback
            print(f"Unexpected labels {unique_labels}, mapping min→0, max→1")
            y = (y == y.max()).astype(int)

        print(f"After mapping: {sorted(y.unique())} (0=Legitimate, 1=Phishing)")
        print(f"Label distribution: {pd.Series(y).value_counts().to_dict()}")
        print(f"Dataset: {X.shape[0]} samples, {X.shape[1]} features")

        # Scale and split
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=test_size, random_state=RANDOM_STATE, stratify=y
        )

        # Build model
        self.model = self._build_model(X_train.shape[1])

        print("\nTraining model...")
        self.model.summary()

        # Train with early stopping
        early_stop = tf.keras.callbacks.EarlyStopping(
            monitor='val_loss', patience=PATIENCE, restore_best_weights=True, verbose=1
        )

        self.model.fit(
            X_train, y_train,
            epochs=epochs,
            batch_size=batch_size,
            validation_data=(X_test, y_test),
            callbacks=[early_stop],
            verbose=2
        )

        # Evaluate
        self._evaluate(X_test, y_test)

        # Save
        self.save()

    def _build_model(self, input_dim):
        """Build neural network architecture"""
        model = tf.keras.Sequential([
            tf.keras.Input(shape=(input_dim,)),
            tf.keras.layers.Dense(64, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.001)),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(32, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.001)),
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.Dense(16, activation='relu'),
            tf.keras.layers.Dense(2, activation='softmax')
        ])

        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=LEARNING_RATE),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        return model

    def _evaluate(self, X_test, y_test):
        """Print evaluation metrics"""
        print("\n=== EVALUATION ===")
        loss, acc = self.model.evaluate(X_test, y_test, verbose=0)
        print(f"Test Loss: {loss:.4f}, Accuracy: {acc:.4f}")

        y_pred = self.model.predict(X_test, verbose=0).argmax(axis=1)

        print("\nConfusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        print(f"              Predicted")
        print(f"              Legit  Phishing")
        print(f"Actual Legit    {cm[0][0]:5d}  {cm[0][1]:5d}")
        print(f"Actual Phishing {cm[1][0]:5d}  {cm[1][1]:5d}")

        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

    def save(self, model_path=MODEL_PATH, scaler_path=SCALER_PATH):
        """Save model and scaler"""
        self.model.save(model_path)
        joblib.dump(self.scaler, scaler_path)
        print(f"\n✅ Model saved to {model_path}")
        print(f"✅ Scaler saved to {scaler_path}")

    def predict(self, features_df):
        """Predict phishing for feature dataframe"""
        X = self.scaler.transform(features_df)
        probs = self.model.predict(X, verbose=0)
        labels = probs.argmax(axis=1)
        return labels, probs

    def predict_urls(self, urls):
        """Predict phishing for list of URLs"""
        results = []
        for url in urls:
            try:
                print(f"\nAnalyzing: {url}")
                features = FeatureExtractor.extract(url)
                print(f"  Features: {features.iloc[0].to_dict()}")

                labels, probs = self.predict(features)
                label = 'PHISHING' if labels[0] == 1 else 'LEGITIMATE'
                confidence = probs[0].max()

                results.append({
                    'url': url,
                    'prediction': label,
                    'confidence': confidence,
                    'probabilities': {'legitimate': probs[0][0], 'phishing': probs[0][1]},
                    'features': features.iloc[0].to_dict()
                })

                print(f"  → {label} (confidence: {confidence:.3f})")
            except Exception as e:
                print(f"  Error: {e}")
                results.append({'url': url, 'error': str(e)})

        return results

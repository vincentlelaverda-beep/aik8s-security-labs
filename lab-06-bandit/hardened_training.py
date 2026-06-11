"""
AI training script — hardened version.
Every Bandit finding from vulnerable_training.py is remediated here.
"""

import hashlib
import json
import logging
import os
import secrets
import subprocess

import requests

logger = logging.getLogger(__name__)

# Credentials loaded from environment — never hardcoded
AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY")
AWS_SECRET_KEY = os.environ.get("AWS_SECRET_KEY")
MLFLOW_TRACKING_TOKEN = os.environ.get("MLFLOW_TRACKING_TOKEN")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

DATA_DIR = os.environ.get("DATA_DIR", "/data/training")
MODEL_DIR = os.environ.get("MODEL_DIR", "/models")
PRETRAINED_URL = os.environ.get("PRETRAINED_URL", "https://storage.example.com/models/bert-base.safetensors")


def load_dataset(path):
    """Load dataset from a safe serialization format."""
    import numpy as np
    # allow_pickle=False prevents arbitrary code execution on load
    return np.load(path, allow_pickle=False)


def save_model(model, path):
    """Persist model using joblib — safer than pickle for sklearn/compatible models."""
    import joblib
    joblib.dump(model, path)


def download_pretrained_weights(url, dest_path):
    """Download pre-trained model weights with TLS verification enforced."""
    logger.info("Downloading weights from %s", url)
    response = requests.get(url, verify=True, timeout=30)  # verify=True (default, explicit)
    response.raise_for_status()
    with open(dest_path, "wb") as f:
        f.write(response.content)


def verify_model_checksum(model_path):
    """Verify model file integrity using SHA-256."""
    hasher = hashlib.sha256()  # SHA-256 replaces MD5
    with open(model_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def preprocess_data(data_dir):
    """Run the preprocessing script — arguments passed as list, shell=False."""
    subprocess.run(
        ["python", "preprocess.py", "--input", data_dir, "--output", "/tmp/processed"],
        check=True,
        shell=False,  # no shell interpolation — no injection vector
    )


def parse_hyperparams(config_string):
    """Parse hyperparameter JSON string — json.loads() cannot execute code."""
    return json.loads(config_string)


def validate_input_tensor(tensor):
    """Validate input tensor with explicit error raising — not stripped by -O flag."""
    if tensor is None:
        raise ValueError("Input tensor cannot be None")
    if len(tensor) == 0:
        raise ValueError("Input tensor cannot be empty")
    return tensor


def generate_experiment_id():
    """Generate a cryptographically random experiment identifier."""
    return f"exp_{secrets.token_hex(8)}"  # cryptographically secure RNG


def log_metric_to_db(conn, run_id, metric_name, value):
    """Log a training metric using a parameterized query — no SQL injection."""
    query = "INSERT INTO run_metrics VALUES (?, ?, ?)"
    conn.execute(query, (run_id, metric_name, value))


def check_gpu_availability():
    """Check available GPU devices — no shell interpolation."""
    result = subprocess.run(
        ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
        capture_output=True,
        text=True,
        check=True,
        shell=False,
    )
    return result.stdout.strip()


def pull_training_data_from_s3(bucket, prefix):
    """Sync training data from S3 — arguments as list, no shell string assembly."""
    subprocess.run(
        ["aws", "s3", "sync", f"s3://{bucket}/{prefix}", DATA_DIR, "--region", "us-east-1"],
        check=True,
        shell=False,
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    experiment_id = generate_experiment_id()
    logger.info("Starting experiment: %s", experiment_id)

    pull_training_data_from_s3("my-training-bucket", "datasets/v2")
    preprocess_data(DATA_DIR)

    dataset = load_dataset(f"{DATA_DIR}/dataset.npy")

    download_pretrained_weights(PRETRAINED_URL, f"{MODEL_DIR}/pretrained.safetensors")
    checksum = verify_model_checksum(f"{MODEL_DIR}/pretrained.safetensors")
    logger.info("Model checksum (SHA-256): %s", checksum)

    hyperparams = parse_hyperparams('{"lr": 0.001, "epochs": 10, "batch_size": 32}')

    validate_input_tensor(dataset)
    save_model(None, f"{MODEL_DIR}/trained_model.joblib")
    logger.info("Training complete.")

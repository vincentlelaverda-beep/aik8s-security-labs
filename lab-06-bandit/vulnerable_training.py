"""
AI training script — intentionally insecure version.
Used in Lab 06 to demonstrate Bandit SAST findings on realistic ML code.
DO NOT use in production.
"""

import os
import pickle
import hashlib
import random
import subprocess
import requests

# --- Hardcoded credentials (B105 / B106) ---
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
MLFLOW_TRACKING_TOKEN = "mlf-abc123secrettoken9999"
DB_PASSWORD = "training_db_password_123"

DATA_DIR = "/data/training"
MODEL_DIR = "/models"
PRETRAINED_URL = "http://storage.example.com/models/bert-base.pkl"


def load_dataset(path):
    """Load serialized dataset from disk."""
    with open(path, "rb") as f:
        return pickle.load(f)  # B301 — deserializes arbitrary Python objects


def save_model(model, path):
    """Persist trained model to disk."""
    with open(path, "wb") as f:
        pickle.dump(model, f)  # B301 — pickle serialization


def download_pretrained_weights(url, dest_path):
    """Download pre-trained model weights from remote storage."""
    print(f"Downloading weights from {url}...")
    response = requests.get(url, verify=False)  # B501 — SSL verification disabled
    with open(dest_path, "wb") as f:
        f.write(response.content)


def verify_model_checksum(model_path):
    """Verify model file integrity."""
    hasher = hashlib.md5()  # B324 — MD5 is cryptographically weak
    with open(model_path, "rb") as f:
        hasher.update(f.read())
    return hasher.hexdigest()


def preprocess_data(data_dir):
    """Run the preprocessing script on raw data."""
    subprocess.call(  # B602 — shell=True enables command injection
        f"python preprocess.py --input {data_dir} --output /tmp/processed",
        shell=True,
    )


def parse_hyperparams(config_string):
    """Parse hyperparameter string from the experiment config."""
    return eval(config_string)  # B307 — eval() executes arbitrary code


def validate_input_tensor(tensor):
    """Validate that the input tensor is non-empty before inference."""
    assert tensor is not None, "Input tensor cannot be None"   # B101 — assert stripped by -O flag
    assert len(tensor) > 0, "Input tensor cannot be empty"    # B101
    return tensor


def generate_experiment_id():
    """Generate a unique experiment identifier."""
    return f"exp_{random.randint(100000, 999999)}"  # B311 — not cryptographically random


def log_metric_to_db(conn, run_id, metric_name, value):
    """Log a training metric to the experiment database."""
    query = "INSERT INTO run_metrics VALUES ('%s', '%s', %f)" % (  # B608 — SQL injection
        run_id,
        metric_name,
        value,
    )
    conn.execute(query)


def check_gpu_availability():
    """Check available GPU devices via nvidia-smi."""
    result = subprocess.check_output(  # B602 — shell=True
        "nvidia-smi --query-gpu=name,memory.total --format=csv,noheader",
        shell=True,
    )
    return result.decode().strip()


def pull_training_data_from_s3(bucket, prefix):
    """Sync training data from S3 using the AWS CLI."""
    cmd = f"aws s3 sync s3://{bucket}/{prefix} {DATA_DIR} --region us-east-1"
    subprocess.call(cmd, shell=True)  # B602 — bucket / prefix injected into shell string


if __name__ == "__main__":
    experiment_id = generate_experiment_id()
    print(f"Starting experiment: {experiment_id}")

    pull_training_data_from_s3("my-training-bucket", "datasets/v2")
    preprocess_data(DATA_DIR)

    dataset = load_dataset(f"{DATA_DIR}/dataset.pkl")

    download_pretrained_weights(PRETRAINED_URL, f"{MODEL_DIR}/pretrained.pkl")
    checksum = verify_model_checksum(f"{MODEL_DIR}/pretrained.pkl")
    print(f"Model checksum: {checksum}")

    hyperparams = parse_hyperparams("{'lr': 0.001, 'epochs': 10, 'batch_size': 32}")

    validate_input_tensor(dataset)
    save_model(None, f"{MODEL_DIR}/trained_model.pkl")
    print("Training complete.")

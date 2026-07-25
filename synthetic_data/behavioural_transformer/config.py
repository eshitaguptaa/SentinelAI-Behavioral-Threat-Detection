"""Configuration for the Transformer behavioural anomaly detector."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(slots=True)
class TransformerConfig:
    """Hyperparameters for the behavioural Transformer autoencoder."""

    # Sequence
    max_seq_len: int = 64
    pad_token: str = "<PAD>"
    unk_token: str = "<UNK>"
    mask_token: str = "<MASK>"

    # Model
    d_model: int = 64
    nhead: int = 4
    num_layers: int = 3
    dim_feedforward: int = 128
    dropout: float = 0.1

    # Training
    batch_size: int = 32
    learning_rate: float = 1e-3
    weight_decay: float = 1e-4
    max_epochs: int = 40
    patience: int = 6
    validation_fraction: float = 0.15
    anomaly_threshold_percentile: float = 95.0
    random_seed: int = 42
    num_workers: int = 0

    # Inference
    device: str = "cpu"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> TransformerConfig:
        known = {field.name for field in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {key: value for key, value in payload.items() if key in known}
        return cls(**filtered)


DEFAULT_TRANSFORMER_CONFIG = TransformerConfig()

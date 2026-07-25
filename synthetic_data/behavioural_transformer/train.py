"""Training pipeline for the behavioural Transformer autoencoder."""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import torch
from torch import nn
from torch.optim import Adam
from torch.optim.lr_scheduler import ReduceLROnPlateau

from synthetic_data.behavioural_transformer.calibration import ErrorCalibration
from synthetic_data.behavioural_transformer.config import (
    DEFAULT_TRANSFORMER_CONFIG,
    TransformerConfig,
)
from synthetic_data.behavioural_transformer.dataset import build_dataloaders
from synthetic_data.behavioural_transformer.model import BehaviourTransformer
from synthetic_data.behavioural_transformer.schema import SessionSequence
from synthetic_data.behavioural_transformer.sequence_builder import (
    EventVocabulary,
    SequenceBuilder,
)
logger = logging.getLogger(__name__)


@dataclass(slots=True)
class TrainingHistory:
    """Per-epoch training metrics."""

    train_loss: list[float]
    val_loss: list[float]
    best_epoch: int
    best_val_loss: float


@dataclass(slots=True)
class TrainedTransformerArtifact:
    """Bundled model + vocabulary + calibration for persistence."""

    model: BehaviourTransformer
    vocabulary: EventVocabulary
    config: TransformerConfig
    error_mean: float
    error_std: float
    anomaly_threshold: float
    history: TrainingHistory
    calibration: ErrorCalibration | None = None

    def resolved_calibration(self) -> ErrorCalibration:
        """Return empirical calibration, falling back to legacy mean/std/p95."""
        if self.calibration is not None:
            return self.calibration
        return ErrorCalibration.from_legacy(
            mean=self.error_mean,
            std=self.error_std,
            threshold=self.anomaly_threshold,
        )

    def save(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        cal = self.resolved_calibration()
        payload = {
            "format": "sentinelai_behaviour_transformer_v1",
            "config": self.config.to_dict(),
            "vocabulary": self.vocabulary.to_dict(),
            "error_mean": self.error_mean,
            "error_std": self.error_std,
            "anomaly_threshold": self.anomaly_threshold,
            "calibration": cal.to_dict(),
            "history": {
                "train_loss": self.history.train_loss,
                "val_loss": self.history.val_loss,
                "best_epoch": self.history.best_epoch,
                "best_val_loss": self.history.best_val_loss,
            },
            "state_dict": {k: v.cpu() for k, v in self.model.state_dict().items()},
        }
        torch.save(payload, target)
        meta = target.with_suffix(".meta.json")
        meta.write_text(
            json.dumps(
                {
                    "format": payload["format"],
                    "config": payload["config"],
                    "error_mean": self.error_mean,
                    "error_std": self.error_std,
                    "anomaly_threshold": self.anomaly_threshold,
                    "calibration": cal.to_dict(),
                    "vocab_size": self.vocabulary.size,
                    "best_epoch": self.history.best_epoch,
                    "best_val_loss": self.history.best_val_loss,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        logger.info("Saved Transformer artifact to %s", target)
        return target


def train_transformer(
    sequences: Sequence[SessionSequence],
    *,
    config: TransformerConfig | None = None,
    checkpoint_path: str | Path | None = None,
) -> TrainedTransformerArtifact:
    """Train a reconstruction Transformer on normal behavioural sequences."""
    cfg = config or DEFAULT_TRANSFORMER_CONFIG
    if len(sequences) < 2:
        raise ValueError("Need at least 2 session sequences to train")

    torch.manual_seed(cfg.random_seed)
    np.random.seed(cfg.random_seed)

    builder = SequenceBuilder(config=cfg)
    vocabulary = builder.fit_vocabulary(sequences)
    train_loader, val_loader = build_dataloaders(
        sequences,
        builder,
        batch_size=cfg.batch_size,
        validation_fraction=cfg.validation_fraction,
        random_seed=cfg.random_seed,
        num_workers=cfg.num_workers,
    )

    device = torch.device(cfg.device if torch.cuda.is_available() or cfg.device == "cpu" else "cpu")
    model = BehaviourTransformer(
        vocab_size=vocabulary.size,
        d_model=cfg.d_model,
        nhead=cfg.nhead,
        num_layers=cfg.num_layers,
        dim_feedforward=cfg.dim_feedforward,
        dropout=cfg.dropout,
        max_seq_len=cfg.max_seq_len,
        pad_id=vocabulary.pad_id,
    ).to(device)

    optimizer = Adam(model.parameters(), lr=cfg.learning_rate, weight_decay=cfg.weight_decay)
    scheduler = ReduceLROnPlateau(optimizer, mode="min", factor=0.5, patience=2)
    criterion = nn.CrossEntropyLoss(ignore_index=vocabulary.pad_id)

    best_state: dict[str, Any] | None = None
    best_val = float("inf")
    best_epoch = 0
    patience_left = cfg.patience
    train_losses: list[float] = []
    val_losses: list[float] = []

    for epoch in range(1, cfg.max_epochs + 1):
        model.train()
        running = 0.0
        batches = 0
        for batch in train_loader:
            token_ids = batch["token_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            optimizer.zero_grad(set_to_none=True)
            outputs = model(token_ids, attention_mask)
            logits = outputs["logits"]
            loss = criterion(
                logits.reshape(-1, vocabulary.size),
                token_ids.reshape(-1),
            )
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            running += float(loss.item())
            batches += 1
        train_loss = running / max(batches, 1)
        train_losses.append(train_loss)

        val_loss = train_loss
        if val_loader is not None:
            model.eval()
            v_running = 0.0
            v_batches = 0
            with torch.no_grad():
                for batch in val_loader:
                    token_ids = batch["token_ids"].to(device)
                    attention_mask = batch["attention_mask"].to(device)
                    outputs = model(token_ids, attention_mask)
                    logits = outputs["logits"]
                    loss = criterion(
                        logits.reshape(-1, vocabulary.size),
                        token_ids.reshape(-1),
                    )
                    v_running += float(loss.item())
                    v_batches += 1
            val_loss = v_running / max(v_batches, 1)
        val_losses.append(val_loss)
        scheduler.step(val_loss)

        logger.info(
            "Epoch %s/%s train_loss=%.4f val_loss=%.4f",
            epoch,
            cfg.max_epochs,
            train_loss,
            val_loss,
        )

        if val_loss < best_val - 1e-5:
            best_val = val_loss
            best_epoch = epoch
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
            patience_left = cfg.patience
            if checkpoint_path is not None:
                Path(checkpoint_path).parent.mkdir(parents=True, exist_ok=True)
                torch.save(best_state, checkpoint_path)
        else:
            patience_left -= 1
            if patience_left <= 0:
                logger.info("Early stopping at epoch %s (best=%s)", epoch, best_epoch)
                break

    if best_state is not None:
        model.load_state_dict(best_state)

    # Calibration: reconstruction errors on training sequences.
    model.eval()
    errors: list[float] = []
    with torch.no_grad():
        encoded = builder.encode(sequences)
        for start in range(0, len(encoded.token_ids), cfg.batch_size):
            end = start + cfg.batch_size
            token_ids = torch.tensor(encoded.token_ids[start:end], dtype=torch.long, device=device)
            attention_mask = torch.tensor(
                encoded.attention_mask[start:end], dtype=torch.long, device=device
            )
            seq_err, _ = model.reconstruction_errors(token_ids, attention_mask)
            errors.extend(float(x) for x in seq_err.cpu().tolist())

    error_arr = np.asarray(errors, dtype=np.float64)
    calibration = ErrorCalibration.from_errors(error_arr)
    error_mean = calibration.mean
    error_std = calibration.std
    anomaly_threshold = calibration.p95

    history = TrainingHistory(
        train_loss=train_losses,
        val_loss=val_losses,
        best_epoch=best_epoch,
        best_val_loss=best_val,
    )
    return TrainedTransformerArtifact(
        model=model.cpu(),
        vocabulary=vocabulary,
        config=cfg,
        error_mean=error_mean,
        error_std=error_std,
        anomaly_threshold=anomaly_threshold,
        history=history,
        calibration=calibration,
    )


def load_trained_artifact(path: str | Path) -> TrainedTransformerArtifact:
    """Load a previously saved Transformer artifact."""
    payload = torch.load(Path(path), map_location="cpu", weights_only=False)
    if payload.get("format") != "sentinelai_behaviour_transformer_v1":
        raise ValueError(f"Unsupported Transformer artifact format: {payload.get('format')}")

    config = TransformerConfig.from_dict(dict(payload["config"]))
    vocabulary = EventVocabulary.from_dict(dict(payload["vocabulary"]))
    model = BehaviourTransformer(
        vocab_size=vocabulary.size,
        d_model=config.d_model,
        nhead=config.nhead,
        num_layers=config.num_layers,
        dim_feedforward=config.dim_feedforward,
        dropout=config.dropout,
        max_seq_len=config.max_seq_len,
        pad_id=vocabulary.pad_id,
    )
    model.load_state_dict(payload["state_dict"])
    model.eval()
    hist = dict(payload.get("history") or {})
    history = TrainingHistory(
        train_loss=list(hist.get("train_loss") or []),
        val_loss=list(hist.get("val_loss") or []),
        best_epoch=int(hist.get("best_epoch") or 0),
        best_val_loss=float(hist.get("best_val_loss") or 0.0),
    )
    error_mean = float(payload["error_mean"])
    error_std = float(payload["error_std"])
    anomaly_threshold = float(payload["anomaly_threshold"])
    if payload.get("calibration"):
        calibration = ErrorCalibration.from_dict(dict(payload["calibration"]))
    else:
        calibration = ErrorCalibration.from_legacy(
            mean=error_mean,
            std=error_std,
            threshold=anomaly_threshold,
        )
    return TrainedTransformerArtifact(
        model=model,
        vocabulary=vocabulary,
        config=config,
        error_mean=error_mean,
        error_std=error_std,
        anomaly_threshold=anomaly_threshold,
        history=history,
        calibration=calibration,
    )

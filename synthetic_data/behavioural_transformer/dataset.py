"""PyTorch Dataset / DataLoader helpers for session sequences."""

from __future__ import annotations

from collections.abc import Sequence

import torch
from torch.utils.data import DataLoader, Dataset

from synthetic_data.behavioural_transformer.schema import EncodedBatch, SessionSequence
from synthetic_data.behavioural_transformer.sequence_builder import SequenceBuilder


class SessionSequenceDataset(Dataset):
    """Dataset wrapping an ``EncodedBatch``."""

    def __init__(self, batch: EncodedBatch) -> None:
        self._tokens = batch.token_ids
        self._masks = batch.attention_mask
        self._lengths = batch.lengths
        self._identities = batch.identities

    def __len__(self) -> int:
        return len(self._tokens)

    def __getitem__(self, index: int) -> dict[str, torch.Tensor | tuple[str, str, str]]:
        return {
            "token_ids": torch.tensor(self._tokens[index], dtype=torch.long),
            "attention_mask": torch.tensor(self._masks[index], dtype=torch.long),
            "length": torch.tensor(self._lengths[index], dtype=torch.long),
            "identity": self._identities[index],
        }


def build_dataloaders(
    sequences: Sequence[SessionSequence],
    builder: SequenceBuilder,
    *,
    batch_size: int,
    validation_fraction: float,
    random_seed: int,
    num_workers: int = 0,
) -> tuple[DataLoader, DataLoader | None]:
    """Encode sequences and split into train/validation DataLoaders."""
    if not sequences:
        raise ValueError("Cannot build dataloaders from an empty sequence list")

    encoded = builder.encode(sequences)
    n = len(encoded.token_ids)
    generator = torch.Generator().manual_seed(random_seed)
    indices = torch.randperm(n, generator=generator).tolist()

    val_count = int(n * validation_fraction) if n >= 10 else 0
    val_indices = indices[:val_count]
    train_indices = indices[val_count:] or indices

    def _subset(idxs: list[int]) -> EncodedBatch:
        return EncodedBatch(
            token_ids=[encoded.token_ids[i] for i in idxs],
            attention_mask=[encoded.attention_mask[i] for i in idxs],
            lengths=[encoded.lengths[i] for i in idxs],
            identities=[encoded.identities[i] for i in idxs],
        )

    train_loader = DataLoader(
        SessionSequenceDataset(_subset(train_indices)),
        batch_size=batch_size,
        shuffle=True,
        num_workers=num_workers,
    )
    val_loader = None
    if val_indices:
        val_loader = DataLoader(
            SessionSequenceDataset(_subset(val_indices)),
            batch_size=batch_size,
            shuffle=False,
            num_workers=num_workers,
        )
    return train_loader, val_loader

"""Transformer encoder autoencoder for behavioural sequence reconstruction."""

from __future__ import annotations

import math
from typing import Any

import torch
from torch import nn


class PositionalEncoding(nn.Module):
    """Sinusoidal positional encodings added to token embeddings."""

    def __init__(self, d_model: int, *, max_len: int = 512, dropout: float = 0.1) -> None:
        super().__init__()
        self.dropout = nn.Dropout(p=dropout)
        position = torch.arange(0, max_len, dtype=torch.float32).unsqueeze(1)
        div_term = torch.exp(
            torch.arange(0, d_model, 2, dtype=torch.float32) * (-math.log(10000.0) / d_model)
        )
        pe = torch.zeros(max_len, d_model)
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        self.register_buffer("pe", pe.unsqueeze(0), persistent=False)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch, seq, d_model)
        x = x + self.pe[:, : x.size(1)]
        return self.dropout(x)


class BehaviourTransformer(nn.Module):
    """Transformer encoder that reconstructs event-token sequences.

    Architecture:
        Event Embedding → Positional Encoding → Encoder stack →
        reconstruction head (vocab logits) + behaviour embedding (masked mean).
    """

    def __init__(
        self,
        *,
        vocab_size: int,
        d_model: int = 64,
        nhead: int = 4,
        num_layers: int = 3,
        dim_feedforward: int = 128,
        dropout: float = 0.1,
        max_seq_len: int = 64,
        pad_id: int = 0,
    ) -> None:
        super().__init__()
        if d_model % nhead != 0:
            raise ValueError(f"d_model ({d_model}) must be divisible by nhead ({nhead})")

        self.vocab_size = vocab_size
        self.d_model = d_model
        self.pad_id = pad_id
        self.max_seq_len = max_seq_len

        self.embedding = nn.Embedding(vocab_size, d_model, padding_idx=pad_id)
        self.positional = PositionalEncoding(d_model, max_len=max_seq_len, dropout=dropout)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            batch_first=True,
            activation="gelu",
            norm_first=True,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.layer_norm = nn.LayerNorm(d_model)
        self.reconstruction_head = nn.Linear(d_model, vocab_size)

        self._reset_parameters()

    def _reset_parameters(self) -> None:
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
                if module.bias is not None:
                    nn.init.zeros_(module.bias)
            elif isinstance(module, nn.Embedding):
                nn.init.normal_(module.weight, mean=0.0, std=0.02)
                if module.padding_idx is not None:
                    with torch.no_grad():
                        module.weight[module.padding_idx].fill_(0.0)

    def forward(
        self,
        token_ids: torch.Tensor,
        attention_mask: torch.Tensor | None = None,
    ) -> dict[str, torch.Tensor]:
        """Run the encoder and reconstruction head.

        Args:
            token_ids: ``(batch, seq)`` integer token ids.
            attention_mask: ``(batch, seq)`` with 1 = real token, 0 = pad.

        Returns:
            Dict with ``logits``, ``hidden``, ``behaviour_embedding``.
        """
        if attention_mask is None:
            attention_mask = (token_ids != self.pad_id).long()

        embedded = self.embedding(token_ids) * math.sqrt(self.d_model)
        encoded = self.positional(embedded)

        # PyTorch key_padding_mask: True where we should ignore (pads).
        key_padding_mask = attention_mask == 0
        hidden = self.encoder(encoded, src_key_padding_mask=key_padding_mask)
        hidden = self.layer_norm(hidden)
        logits = self.reconstruction_head(hidden)

        mask = attention_mask.unsqueeze(-1).float()
        summed = (hidden * mask).sum(dim=1)
        denom = mask.sum(dim=1).clamp(min=1.0)
        behaviour_embedding = summed / denom

        return {
            "logits": logits,
            "hidden": hidden,
            "behaviour_embedding": behaviour_embedding,
        }

    def reconstruction_errors(
        self,
        token_ids: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        """Return per-sequence mean CE and per-token CE (pad positions → 0)."""
        outputs = self.forward(token_ids, attention_mask)
        logits = outputs["logits"]
        vocab = logits.size(-1)
        flat_logits = logits.reshape(-1, vocab)
        flat_targets = token_ids.reshape(-1)
        token_loss = nn.functional.cross_entropy(
            flat_logits,
            flat_targets,
            reduction="none",
            ignore_index=self.pad_id,
        ).reshape_as(token_ids)

        lengths = attention_mask.sum(dim=1).clamp(min=1).float()
        seq_loss = (token_loss * attention_mask.float()).sum(dim=1) / lengths
        return seq_loss, token_loss

    def extract_attention(
        self,
        token_ids: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> torch.Tensor:
        """Return real last-layer multi-head self-attention weights.

        Runs the encoder stack up to the final layer, then calls that layer's
        ``MultiheadAttention`` with ``need_weights=True`` (averaged over heads).
        Pad positions are zeroed so the heatmap only covers real events.
        """
        if attention_mask is None:
            attention_mask = (token_ids != self.pad_id).long()

        with torch.no_grad():
            embedded = self.embedding(token_ids) * math.sqrt(self.d_model)
            x = self.positional(embedded)
            key_padding_mask = attention_mask == 0

            layers = list(self.encoder.layers)
            if not layers:
                batch, seq_len = token_ids.shape
                return torch.zeros(batch, seq_len, seq_len, device=token_ids.device)

            for layer in layers[:-1]:
                x = layer(x, src_key_padding_mask=key_padding_mask)

            last = layers[-1]
            # Mirror TransformerEncoderLayer(norm_first=True) self-attention path.
            if last.norm_first:
                query = last.norm1(x)
            else:
                query = x

            _attn_out, weights = last.self_attn(
                query,
                query,
                query,
                key_padding_mask=key_padding_mask,
                need_weights=True,
                average_attn_weights=True,
            )
            # weights: (batch, seq, seq)
            weights = torch.nan_to_num(weights, nan=0.0)
            valid = attention_mask.float()
            weights = weights * valid.unsqueeze(1) * valid.unsqueeze(2)
            return weights

    def get_config_dict(self) -> dict[str, Any]:
        return {
            "vocab_size": self.vocab_size,
            "d_model": self.d_model,
            "pad_id": self.pad_id,
            "max_seq_len": self.max_seq_len,
        }

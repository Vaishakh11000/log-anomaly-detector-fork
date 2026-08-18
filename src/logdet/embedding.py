"""
embedding.py
Converts templated log messages into dense vector embeddings using a
pretrained sentence-transformer. These embeddings let us measure
*semantic* similarity between log lines rather than exact string matches.
"""

import numpy as np
import pandas as pd
from sentence_transformers import SentenceTransformer

from logdet.config import EMBEDDING_BATCH_SIZE, EMBEDDING_MODEL

_model = None


def get_model():
    global _model
    if _model is None:
        _model = SentenceTransformer(EMBEDDING_MODEL)
    return _model


def embed_templates(templates: list[str]) -> np.ndarray:
    """Embed a list of templated log messages. Returns an (N, D) array."""
    model = get_model()
    embeddings = model.encode(templates, show_progress_bar=True,
                              batch_size=EMBEDDING_BATCH_SIZE)
    return np.array(embeddings)


def add_embeddings_to_df(df: pd.DataFrame, template_col: str = "template") -> pd.DataFrame:
    """Adds an 'embedding' column (as list) to the dataframe."""
    embeddings = embed_templates(df[template_col].fillna("").tolist())
    df = df.copy()
    df["embedding"] = list(embeddings)
    return df


if __name__ == "__main__":
    # quick smoke test
    samples = [
        "Failed password for <USER> from <IP> port <PORT> ssh2",
        "Authentication failure for <USER> from <IP>",
        "Accepted password for <USER> from <IP> port <PORT> ssh2",
    ]
    vecs = embed_templates(samples)
    print("Embedding shape:", vecs.shape)

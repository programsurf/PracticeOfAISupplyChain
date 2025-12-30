#!/usr/bin/env python3
"""
Download sentence-transformers/all-MiniLM-L6-v2 model and save as small_model.pt
"""

import torch
from transformers import AutoModel

print("Downloading sentence-transformers/all-MiniLM-L6-v2...")
model = AutoModel.from_pretrained("sentence-transformers/all-MiniLM-L6-v2")

print("Saving model to models/small_model.pt...")
torch.save(model, "models/small_model.pt")

print("Done! Model saved successfully.")

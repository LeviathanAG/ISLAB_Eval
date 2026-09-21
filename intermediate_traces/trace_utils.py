"""Formatting/loading helpers shared by the additive trace scripts."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def heading(title: str) -> None:
    print(f"\n{'=' * 12} {title} {'=' * 12}")


def aes_matrix(state: bytes) -> str:
    """Format AES's column-major 16 bytes as the usual 4x4 state."""
    return "\n".join(" ".join(f"{state[4 * column + row]:02x}"
                               for column in range(4)) for row in range(4))


def bits(value: int, width: int) -> str:
    return f"{value:0{width}b}"

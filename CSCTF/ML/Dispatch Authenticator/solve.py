"""Recover the private training input from one federated-learning update (gradient leakage).

Usage: python -I solve.py [dispatch-authenticator.npz]
Default path: the handout in the user's Downloads folder.
"""
import os
import sys

import numpy as np


def recover(npz_path):
    z = np.load(npz_path, allow_pickle=False)  # plain arrays only, no pickle execution

    # Single-sample update: dW1 = delta (outer) x, db1 = delta, so each active row gives x = dW1[i] / db1[i].
    W, b = z["update_W1"], z["update_b1"]
    rows = np.flatnonzero(np.abs(b) > 1e-9)  # ReLU-dead units have delta = 0 and carry nothing
    X = W[rows] / b[rows, None]
    assert np.allclose(X, X[0]), "rows disagree, so this was not a single-sample update"
    x = X[0]

    flag = bytes(np.rint(x * 255).astype(np.uint8)).decode()

    # Check 1: the shared model on the recovered input reproduces the intercepted read-out.
    h = np.maximum(0, z["global_W1"] @ x + z["global_b1"])
    logits = z["global_W2"] @ h + z["global_b2"]
    assert np.allclose(logits, z["logits"]), "forward pass does not match intercepted logits"

    # Check 2: the cross-entropy gradient for the given label matches the update up to one scale (the LR).
    p = np.exp(logits - logits.max()); p /= p.sum()
    g_b2 = p - np.eye(len(p))[int(z["label"])]
    scale = z["update_b2"] @ g_b2 / (g_b2 @ g_b2)
    assert np.allclose(z["update_b2"], scale * g_b2), "update is not a CE gradient for this label"
    return flag, scale


def demo():
    """Self-check: a one-sample dense layer leaks its input exactly as dW1/db1, with no optimisation."""
    rng = np.random.default_rng(0)
    x = rng.random(6)
    delta = rng.standard_normal(5)
    dW1 = np.outer(delta, x)          # what backprop stores for the weight gradient
    db1 = delta                       # ...and the bias gradient
    rows = np.flatnonzero(np.abs(db1) > 1e-9)
    xrec = (dW1[rows] / db1[rows, None])[0]
    assert np.allclose(xrec, x), "gradient-leak identity broken"
    print("demo ok: x = dW1/db1 recovered the input exactly")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        demo(); sys.exit()
    default = os.path.expanduser(r"~\Downloads\dispatch-authenticator.npz")
    path = sys.argv[1] if len(sys.argv) > 1 else (
        "dispatch-authenticator.npz" if os.path.exists("dispatch-authenticator.npz") else default)
    flag, scale = recover(path)
    print("flag:  ", flag)
    print(f"verified: logits match, update = {scale:.4g} x cross-entropy gradient")
    assert flag == "CSCTF{17_hansoms_scald_not_aft_ay_gangling_1a7d12}"

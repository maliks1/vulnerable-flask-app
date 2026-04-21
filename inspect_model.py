"""
inspect_model.py — Debug script untuk inspeksi format model_sqli_nb.pkl
Jalankan: .venv/Scripts/python.exe inspect_model.py
"""

import os
import pickle
import sys

MODEL_PATH = "model_sqli_nb.pkl"

print("=" * 60)
print("  SQLi Model Inspector")
print("=" * 60)

# ── 1. Cek file ───────────────────────────────────────────────
if not os.path.exists(MODEL_PATH):
    print(f"[ERROR] File tidak ditemukan: {MODEL_PATH}")
    sys.exit(1)

size = os.path.getsize(MODEL_PATH)
print(f"\n[FILE] {MODEL_PATH}  ({size:,} bytes)")

with open(MODEL_PATH, "rb") as f:
    raw = f.read(32)

print(f"[FILE] First 32 bytes (hex): {raw.hex()}")
print(f"[FILE] First 32 bytes (repr): {raw!r}")

# ── 2. Deteksi format ─────────────────────────────────────────
# Pickle protocol signatures
# \x80\x02 = proto 2, \x80\x03 = proto 3, \x80\x04 = proto 4, \x80\x05 = proto 5
# Joblib (numpy memmap) biasanya dimulai berbeda

is_pickle = raw[0] == 0x80 and raw[1] in (2, 3, 4, 5)
print(f"\n[FORMAT] Looks like pickle: {is_pickle}")
if is_pickle:
    print(f"[FORMAT] Pickle protocol: {raw[1]}")

# ── 3. Coba load dengan pickle ────────────────────────────────
print("\n[PICKLE] Mencoba pickle.load() ...")
obj = None
try:
    with open(MODEL_PATH, "rb") as f:
        obj = pickle.load(f)
    print(f"[PICKLE] Berhasil! Type: {type(obj)}")
except Exception as e:
    print(f"[PICKLE] Gagal: {type(e).__name__}: {e}")

# ── 4. Coba load dengan joblib ────────────────────────────────
if obj is None:
    print("\n[JOBLIB] Mencoba joblib.load() ...")
    try:
        import joblib

        obj = joblib.load(MODEL_PATH)
        print(f"[JOBLIB] Berhasil! Type: {type(obj)}")
    except ImportError:
        print("[JOBLIB] joblib tidak terinstall, skip.")
    except Exception as e:
        print(f"[JOBLIB] Gagal: {type(e).__name__}: {e}")

# ── 5. Inspeksi objek ────────────────────────────────────────
if obj is None:
    print("\n[RESULT] Tidak bisa load model. Periksa format file.")
    sys.exit(1)

print("\n" + "=" * 60)
print("  Inspeksi Objek")
print("=" * 60)
print(f"Type            : {type(obj)}")
print(f"Module          : {type(obj).__module__}")
print(f"Has predict     : {hasattr(obj, 'predict')}")
print(f"Has predict_proba: {hasattr(obj, 'predict_proba')}")
print(f"Has named_steps : {hasattr(obj, 'named_steps')}")
print(f"Has fit         : {hasattr(obj, 'fit')}")
print(f"Is tuple        : {isinstance(obj, tuple)}")
print(f"Is list         : {isinstance(obj, list)}")
print(f"Is dict         : {isinstance(obj, dict)}")

# ── 6. Pipeline ───────────────────────────────────────────────
if hasattr(obj, "named_steps"):
    print("\n[PIPELINE] Ditemukan sklearn Pipeline!")
    print(f"  Steps: {list(obj.named_steps.keys())}")
    for name, step in obj.named_steps.items():
        print(f"  - '{name}': {type(step).__name__}")
    if hasattr(obj, "classes_"):
        print(f"  classes_: {obj.classes_}")

# ── 7. Bare model / estimator ─────────────────────────────────
elif hasattr(obj, "predict") and not isinstance(obj, (tuple, list, dict)):
    print("\n[MODEL] Ditemukan bare estimator (tanpa vectorizer)!")
    print(f"  Kelas : {type(obj).__name__}")
    if hasattr(obj, "classes_"):
        print(f"  classes_: {obj.classes_}")
    if hasattr(obj, "n_features_in_"):
        print(f"  n_features_in_: {obj.n_features_in_}")

# ── 8. Tuple ─────────────────────────────────────────────────
elif isinstance(obj, tuple):
    print(f"\n[TUPLE] Panjang tuple: {len(obj)}")
    for i, item in enumerate(obj):
        print(f"  [{i}] {type(item).__name__}", end="")
        if hasattr(item, "predict"):
            print(" ← model/estimator", end="")
        if hasattr(item, "transform") and not hasattr(item, "predict"):
            print(" ← vectorizer/transformer", end="")
        if hasattr(item, "classes_"):
            print(f"  classes_={getattr(item, 'classes_', None)}", end="")
        if hasattr(item, "n_features_in_"):
            print(f"  n_features_in_={getattr(item, 'n_features_in_', None)}", end="")
        print()

# ── 9. Dict ──────────────────────────────────────────────────
elif isinstance(obj, dict):
    print(f"\n[DICT] Keys: {list(obj.keys())}")
    for k, v in obj.items():
        print(f"  '{k}': {type(v).__name__}", end="")
        if hasattr(v, "classes_"):
            print(f"  classes_={getattr(v, 'classes_', None)}", end="")
        print()

# ── 10. Coba prediksi sampel ──────────────────────────────────
print("\n" + "=" * 60)
print("  Uji Prediksi")
print("=" * 60)

SAMPLES = [
    ("' OR '1'='1' --", "SQLi classic bypass"),
    ("admin' --", "SQLi comment bypass"),
    ("' UNION SELECT 1,2 --", "SQLi union-based"),
    ("admin", "Legitimate username"),
    ("user@email.com", "Legitimate email"),
    ("John Doe", "Legitimate name"),
]


def try_predict(estimator, vectorizer, sample):
    """Coba predict dengan berbagai kombinasi."""
    if hasattr(estimator, "named_steps"):
        # Pipeline
        try:
            label = estimator.predict([sample])[0]
            proba = (
                estimator.predict_proba([sample])[0]
                if hasattr(estimator, "predict_proba")
                else None
            )
            return label, proba
        except Exception as e:
            return f"ERROR: {e}", None
    elif vectorizer is not None:
        try:
            X = vectorizer.transform([sample])
            label = estimator.predict(X)[0]
            proba = (
                estimator.predict_proba(X)[0]
                if hasattr(estimator, "predict_proba")
                else None
            )
            return label, proba
        except Exception as e:
            return f"ERROR: {e}", None
    else:
        try:
            label = estimator.predict([sample])[0]
            proba = (
                estimator.predict_proba([sample])[0]
                if hasattr(estimator, "predict_proba")
                else None
            )
            return label, proba
        except Exception as e:
            return f"ERROR: {e}", None


# Tentukan estimator & vectorizer
vectorizer = None
estimator = None

if hasattr(obj, "named_steps"):
    estimator = obj
elif isinstance(obj, tuple) and len(obj) == 2:
    # Coba tebak mana vectorizer, mana model
    a, b = obj
    if hasattr(a, "predict") and not hasattr(b, "predict"):
        estimator, vectorizer = a, None  # a adalah model, b bukan
    elif hasattr(b, "predict") and not hasattr(a, "predict"):
        estimator, vectorizer = b, a
    elif hasattr(b, "predict") and hasattr(a, "transform"):
        vectorizer, estimator = a, b
    else:
        estimator = b
        vectorizer = a
elif isinstance(obj, dict):
    estimator = (
        obj.get("model") or obj.get("classifier") or obj.get("clf") or obj.get("nb")
    )
    vectorizer = obj.get("vectorizer") or obj.get("vect") or obj.get("tfidf")
elif hasattr(obj, "predict"):
    estimator = obj

if estimator is None:
    print("[ERROR] Tidak bisa menentukan estimator dari objek pkl.")
    sys.exit(1)

print(f"Estimator  : {type(estimator).__name__}")
print(
    f"Vectorizer : {type(vectorizer).__name__ if vectorizer else 'None (embedded in Pipeline atau tidak ada)'}"
)
print()

for payload, desc in SAMPLES:
    label, proba = try_predict(estimator, vectorizer, payload)
    if proba is not None:
        prob_str = "  proba=" + str([round(p, 4) for p in proba])
    else:
        prob_str = ""
    print(f"  [{desc:30s}] label={label}{prob_str}")

print("\n[DONE] Inspeksi selesai.")
print("\nSalin output ini dan tempel ke chat agar middleware.py bisa disesuaikan.")

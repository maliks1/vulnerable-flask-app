"""
middleware.py — ML-based SQL Injection detection for Flask
==========================================================

Exposes
-------
  SQLiDetector   : loads model_sqli_nb.pkl and classifies raw text
  register_middleware(app, detector, protected_endpoints)
                 : attaches a before_request guard to a Flask app

Supported pickle formats
------------------------
  1. sklearn.pipeline.Pipeline          — used directly
  2. tuple / list  (vectorizer, model)  — unpacked
  3. dict  { 'vectorizer': …, 'model': … }
  4. bare model only (predict / predict_proba must exist)
     → in this case the pickle MUST be a Pipeline or the vectorizer
       must be bundled; a RuntimeError is raised on first call otherwise.

Label normalisation
-------------------
  The detector maps any raw model label to one of two strings:
    'sqli'        — request is malicious
    'legitimate'  — request is benign
  Recognised "sqli" raw labels (case-insensitive):
    1, 1.0, '1', 'sqli', 'sql injection', 'malicious', 'bad', 'attack',
    'injection', 'anomaly', 'abnormal', 'yes', 'true', 'positive'
"""

from __future__ import annotations

import logging
import os
import pickle
import re
from typing import Any, Dict, Optional, Tuple

try:
    import joblib as _joblib

    _HAS_JOBLIB = True
except ImportError:
    _joblib = None  # type: ignore[assignment]
    _HAS_JOBLIB = False

from flask import redirect, request, session, url_for

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Label sets
# ---------------------------------------------------------------------------

_SQLI_LABELS: frozenset[str] = frozenset(
    {
        "1",
        "1.0",
        "sqli",
        "sqli",
        "sql injection",
        "sql_injection",
        "malicious",
        "bad",
        "attack",
        "injection",
        "anomaly",
        "abnormal",
        "yes",
        "true",
        "positive",
    }
)

_LEGIT_LABELS: frozenset[str] = frozenset(
    {
        "0",
        "0.0",
        "legitimate",
        "normal",
        "benign",
        "clean",
        "safe",
        "good",
        "no",
        "false",
        "negative",
    }
)

# Regex untuk input yang jelas-jelas aman — tidak perlu dijalankan ke ML.
# Hanya mengizinkan: huruf, angka, underscore (\w), spasi, @, titik,
# tanda hubung, plus, maksimal 200 karakter.
# Input yang mengandung karakter SQL ( ' ; -- ( ) dll.) TIDAK akan cocok
# dan akan tetap diperiksa oleh model ML.
# Tujuan: mencegah false positive pada string pendek seperti "admin" atau
# "alice" yang sering muncul di contoh SQLi dalam dataset pelatihan.
_SAFE_INPUT_RE = re.compile(r"^[\w\s@.\-+]{1,200}$", re.ASCII)


# ---------------------------------------------------------------------------
# SQLiDetector
# ---------------------------------------------------------------------------


class SQLiDetector:
    """
    Flexible loader + classifier for Naive Bayes SQLi detection models.

    Parameters
    ----------
    model_path : str
        Path to the pickle file produced during training.
        File dapat disimpan dengan joblib.dump() atau pickle.dump().
        Loader mencoba joblib terlebih dahulu, lalu fallback ke pickle.
    threshold  : float
        Minimum probability untuk kelas SQLi agar request diblokir.
        Default 0.85 — cukup ketat untuk menekan false positive
        (mis. username "admin" yang salah diklasifikasi sebagai SQLi).
        Turunkan ke 0.50 untuk sensitivitas penuh (lebih banyak false positive).
    """

    def __init__(
        self,
        model_path: str = "model_sqli_nb.pkl",
        threshold: float = 0.85,
        use_prefilter: bool = True,
    ) -> None:
        self.threshold = threshold
        # Pre-filter: jika True, input yang hanya berisi karakter aman
        # ([\w\s@.\-+]) langsung dikembalikan sebagai 'legitimate' tanpa
        # memanggil model ML — menghindari false positive pada "admin", "alice", dsb.
        self.use_prefilter = use_prefilter
        self.pipeline: Optional[Any] = None  # sklearn Pipeline (contains vectorizer)
        self.vectorizer: Optional[Any] = None  # standalone vectorizer
        self.model: Optional[Any] = None  # standalone classifier
        self._classes: Optional[Any] = None  # raw class array from the model

        self._load(model_path)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load(self, path: str) -> None:
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"[SQLiDetector] Model file not found: '{path}'\n"
                "Make sure model_sqli_nb.pkl is in the working directory."
            )

        obj = None
        last_error: Optional[Exception] = None

        # ── Coba joblib dulu (sklearn biasanya disimpan dengan joblib) ──────
        if _HAS_JOBLIB and _joblib is not None:
            try:
                obj = _joblib.load(path)
                logger.info("[SQLiDetector] Loaded with joblib from '%s'", path)
            except Exception as exc:
                last_error = exc
                logger.warning(
                    "[SQLiDetector] joblib.load failed (%s), trying pickle…", exc
                )

        # ── Fallback ke pickle ───────────────────────────────────────────────
        if obj is None:
            try:
                with open(path, "rb") as fh:
                    obj = pickle.load(fh)
                logger.info("[SQLiDetector] Loaded with pickle from '%s'", path)
            except Exception as exc:
                last_error = exc
                logger.error("[SQLiDetector] pickle.load also failed: %s", exc)

        if obj is None:
            raise RuntimeError(
                f"[SQLiDetector] Tidak bisa memuat model dari '{path}'.\n"
                f"Error terakhir: {last_error}\n"
                "Pastikan file disimpan dengan joblib.dump() atau pickle.dump()."
            )

        # ① sklearn Pipeline  (has .named_steps)
        if hasattr(obj, "named_steps"):
            self.pipeline = obj
            self._classes = getattr(obj, "classes_", None)
            logger.info("[SQLiDetector] Loaded sklearn Pipeline from '%s'", path)

        # ② tuple / list  →  (vectorizer, model)
        elif isinstance(obj, (tuple, list)) and len(obj) == 2:
            self.vectorizer, self.model = obj
            self._classes = getattr(self.model, "classes_", None)
            logger.info(
                "[SQLiDetector] Loaded (vectorizer, model) tuple from '%s'", path
            )

        # ③ dict  →  {'vectorizer': …, 'model': …}
        elif isinstance(obj, dict):
            self.vectorizer = (
                obj.get("vectorizer")
                or obj.get("vect")
                or obj.get("tfidf")
                or obj.get("cv")
            )
            self.model = (
                obj.get("model")
                or obj.get("classifier")
                or obj.get("clf")
                or obj.get("nb")
            )
            if self.model is None:
                raise ValueError(
                    "[SQLiDetector] Dict pickle must contain a key like "
                    "'model', 'classifier', 'clf', or 'nb'."
                )
            self._classes = getattr(self.model, "classes_", None)
            logger.info("[SQLiDetector] Loaded dict-format pickle from '%s'", path)

        # ④ bare model
        elif hasattr(obj, "predict"):
            self.model = obj
            self._classes = getattr(obj, "classes_", None)
            logger.warning(
                "[SQLiDetector] Loaded bare model from '%s' — no vectorizer "
                "bundled.  Predictions will fail unless the model is a "
                "Pipeline or accepts raw strings.",
                path,
            )

        else:
            raise ValueError(
                f"[SQLiDetector] Unrecognised pickle format: {type(obj)}.  "
                "Save the model as a Pipeline or (vectorizer, model) tuple."
            )

    def _vectorize(self, text: str):
        """Transform raw text using the bundled vectorizer."""
        if self.vectorizer is None:
            raise RuntimeError(
                "[SQLiDetector] No vectorizer found in the pickle file.  "
                "Re-save the model as:\n"
                "  • sklearn.pipeline.Pipeline([('vect', vectorizer), ('clf', model)])\n"
                "  • tuple: (vectorizer, model)\n"
                "  • dict:  {'vectorizer': …, 'model': …}"
            )
        return self.vectorizer.transform([text])

    @staticmethod
    def _normalise_label(raw: Any) -> str:
        """Map any raw label to 'sqli' or 'legitimate'."""
        key = str(raw).strip().lower()
        if key in _SQLI_LABELS:
            return "sqli"
        if key in _LEGIT_LABELS:
            return "legitimate"
        # fallback: non-zero numeric → sqli
        try:
            return "sqli" if float(key) != 0 else "legitimate"
        except (ValueError, TypeError):
            pass
        logger.warning(
            "[SQLiDetector] Unknown label '%s' — treating as 'legitimate'", raw
        )
        return "legitimate"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def predict_proba_map(self, text: str) -> Dict[str, float]:
        """
        Return a dict mapping each raw class label → probability.

        Example (binary model with labels 0 / 1):
            {'0': 0.032, '1': 0.968}
        """
        try:
            if self.pipeline is not None:
                raw_proba = self.pipeline.predict_proba([text])[0]
                classes = getattr(self.pipeline, "classes_", range(len(raw_proba)))
            elif self.model is not None:
                X = self._vectorize(text)
                raw_proba = self.model.predict_proba(X)[0]
                classes = (
                    self._classes
                    if self._classes is not None
                    else range(len(raw_proba))
                )
            else:
                raise RuntimeError("[SQLiDetector] No pipeline or model loaded.")
            return {str(c): float(p) for c, p in zip(classes, raw_proba)}

        except AttributeError:
            # Model does not support predict_proba → hard predict only
            if self.pipeline is not None:
                raw_label = self.pipeline.predict([text])[0]
            elif self.model is not None:
                X = self._vectorize(text)
                raw_label = self.model.predict(X)[0]
            else:
                raise RuntimeError("[SQLiDetector] No pipeline or model loaded.")
            label = self._normalise_label(raw_label)
            return {
                "sqli": 1.0 if label == "sqli" else 0.0,
                "legitimate": 0.0 if label == "sqli" else 1.0,
            }

    def predict(self, text: str) -> Tuple[str, float, Dict[str, float]]:
        """
        Classify *text* and return a 3-tuple:

            (label, confidence, proba_map)

        label      : 'sqli' | 'legitimate'
        confidence : float in [0, 1] — probability of the predicted class
        proba_map  : full dict of raw_label → probability
        """
        if not text or not text.strip():
            return "legitimate", 1.0, {"legitimate": 1.0}

        # ── Pre-filter: lewati ML untuk input yang jelas-jelas aman ─────────
        # Input seperti "admin", "alice", "user@mail.com" tidak mengandung
        # karakter SQL apapun → kembalikan langsung sebagai legitimate.
        # Karakter pemicu SQLi ( ' " ; -- ( ) UNION SELECT dll. ) akan
        # menyebabkan regex TIDAK cocok → tetap diperiksa ML.
        if self.use_prefilter and _SAFE_INPUT_RE.match(text):
            logger.debug("[SQLiDetector] Pre-filter pass (no SQL metachar): %r", text)
            return "legitimate", 0.95, {"0": 0.95, "1": 0.05}

        proba_map = self.predict_proba_map(text)

        # Find the raw label with the highest probability
        raw_best = max(proba_map, key=lambda k: proba_map[k])
        confidence = proba_map[raw_best]
        label = self._normalise_label(raw_best)

        # Apply threshold: if the SQLi-class probability is below threshold,
        # treat as legitimate even if it is the argmax.
        # Threshold default 0.85 mengurangi false positive pada input pendek
        # seperti username "admin" yang bisa terklasifikasi sbg SQLi.
        if label == "sqli" and confidence < self.threshold:
            label = "legitimate"

        return label, confidence, proba_map

    def is_sqli(self, text: str) -> bool:
        """Convenience wrapper — returns True when SQLi is detected."""
        label, _, _ = self.predict(text)
        return label == "sqli"

    # ------------------------------------------------------------------
    # String representation
    # ------------------------------------------------------------------

    def __repr__(self) -> str:  # pragma: no cover
        kind = (
            "Pipeline"
            if self.pipeline is not None
            else "(vectorizer, model)"
            if self.vectorizer is not None
            else "bare model"
        )
        return (
            f"SQLiDetector(type={kind}, "
            f"classes={self._classes}, "
            f"threshold={self.threshold}, "
            f"prefilter={self.use_prefilter}, "
            f"loader={'joblib' if _HAS_JOBLIB and _joblib is not None else 'pickle'})"
        )


# ---------------------------------------------------------------------------
# Flask middleware factory
# ---------------------------------------------------------------------------


def register_middleware(
    app,
    detector: SQLiDetector,
    protected_endpoints: tuple[str, ...] = ("protected_login",),
    block_endpoint: str = "blocked",
) -> None:
    """
    Attach a before_request hook to *app* that checks every POST field
    arriving at any of the *protected_endpoints*.

    On detection the function stores detection info in the session and
    redirects to *block_endpoint*.

    Parameters
    ----------
    app                  : Flask application instance
    detector             : SQLiDetector instance
    protected_endpoints  : tuple of Flask endpoint names to guard
    block_endpoint       : endpoint name for the "blocked" page
    """

    @app.before_request
    def _sqli_guard():
        # Only intercept POST requests to the guarded endpoints
        if request.method != "POST":
            return None
        if request.endpoint not in protected_endpoints:
            return None

        form_data = request.form.to_dict()
        for field_name, value in form_data.items():
            if not value:
                continue

            label, confidence, proba_map = detector.predict(value)

            if label == "sqli":
                logger.warning(
                    "[SQLiMiddleware] BLOCKED field='%s' confidence=%.2f%%  payload=%r",
                    field_name,
                    confidence * 100,
                    value[:120],
                )
                # Store detection context in server-side session
                session["blocked_payload"] = value
                session["blocked_field"] = field_name
                session["blocked_confidence"] = round(confidence, 6)
                session["blocked_proba_map"] = {
                    k: round(v, 6) for k, v in proba_map.items()
                }
                return redirect(url_for(block_endpoint))

        return None  # allow the request to continue

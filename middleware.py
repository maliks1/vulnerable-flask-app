"""
middleware.py - Deteksi SQL Injection berbasis Machine Learning untuk Flask
========================================================================

Exposes
-------
  SQLiDetector   : Memuat model Naive Bayes dan mengklasifikasikan teks mentah
  register_middleware(app, detector, protected_endpoints)
                 : Menempelkan before_request guard pada aplikasi Flask
"""

from __future__ import annotations

import logging
import os
import pickle
import re
from typing import Any, Dict, Optional, Tuple
import time

try:
    import joblib as _joblib
    _HAS_JOBLIB = True
except ImportError:
    _joblib = None  # type: ignore[assignment]
    _HAS_JOBLIB = False

from flask import redirect, request, session, url_for, g

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Label Sets
# ---------------------------------------------------------------------------

_SQLI_LABELS: frozenset[str] = frozenset(
    {
        "1",
        "1.0",
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

# ---------------------------------------------------------------------------
# Preprocessing Constants (dari notebook)
# ---------------------------------------------------------------------------

STOPWORDS = {
    "a", "an", "the", "is", "it", "in", "on", "at", "to", "for",
    "of", "and", "with", "by", "as", "be", "was", "are", "were",
    "this", "that", "have", "has", "had", "do", "does", "did",
    "but", "so", "if", "then", "than", "its", "into", "from",
    "there", "their", "they", "will", "would", "could", "should"
}

SQL_KEYWORDS = {
    "select", "from", "where", "and", "or", "not", "is", "in",
    "like", "union", "insert", "update", "delete", "drop", "create",
    "table", "into", "values", "order", "by", "group", "having",
    "join", "on", "null", "true", "false", "case", "when", "then",
    "else", "end", "limit", "offset", "between", "exists", "all",
    "distinct", "count", "sum", "max", "min", "avg", "sleep",
    "benchmark", "char", "concat", "substring", "load_file",
    "outfile", "exec", "execute", "cast", "convert", "if"
}

DROPPED_WORDS = STOPWORDS - SQL_KEYWORDS

# Pre-compiled regex patterns untuk performa optimal
REGEX_SINGLE_QUOTE = re.compile(r"'[^']*'")
REGEX_DOUBLE_QUOTE = re.compile(r'"[^"]*"')
REGEX_DIGITS = re.compile(r'\d+')
REGEX_TOKENS = re.compile(r"[a-z0-9_]+|--|/\*|\*/|'|\"|\(|\)|=|<|>|;|\#|,|\*|\+|\-|%")

# Regex untuk input aman - lewati pemanggilan model ML
_SAFE_INPUT_RE = re.compile(r"^[\w\s@.\-+]{1,200}$", re.ASCII)


# ---------------------------------------------------------------------------
# Preprocessing Functions
# ---------------------------------------------------------------------------

def preprocess_text(text: str) -> str:
    """
    Fungsi preprocessing teks versi optimasi tinggi.
    Menggunakan single lookup berbasis reduksi set logika untuk performa maksimal.
    Sama dengan yang digunakan di notebook untuk konsistensi pipeline.
    """
    if not isinstance(text, str):
        return ""
    
    # 1. Normalisasi case di awal
    text = text.lower()

    # 2. Eksekusi Regex terkompilasi
    text = REGEX_SINGLE_QUOTE.sub("'str'", text)
    text = REGEX_DOUBLE_QUOTE.sub('"str"', text)
    text = REGEX_DIGITS.sub('0', text)

    # 3. Tokenisasi cepat
    tokens = REGEX_TOKENS.findall(text)

    # 4. OPTIMASI LOOP: Mengurangi beban lookup ganda menjadi single lookup
    filtered = [t for t in tokens if t not in DROPPED_WORDS]

    return " ".join(filtered)


# ---------------------------------------------------------------------------
# SQLiDetector
# ---------------------------------------------------------------------------

class SQLiDetector:
    """
    Loader dan classifier fleksibel untuk model deteksi SQLi Naive Bayes.
    """

    def __init__(
        self,
        model_path: str = "model_sqli_nb.pkl",
        threshold: float = 0.85,
        use_prefilter: bool = True,
    ) -> None:
        self.threshold = threshold
        self.use_prefilter = use_prefilter
        self.pipeline: Optional[Any] = None  # sklearn Pipeline (contains vectorizer)
        self.vectorizer: Optional[Any] = None  # standalone vectorizer
        self.model: Optional[Any] = None  # standalone classifier
        self._classes: Optional[Any] = None  # raw class array from the model
        
        # Cache internal untuk mempercepat prediksi berulang (LRU Cache style)
        self._cache: Dict[str, Tuple[str, float, Dict[str, float]]] = {}
        self._max_cache_size = 2048

        self._load(model_path)

    # ------------------------------------------------------------------
    # Private Helpers
    # ------------------------------------------------------------------

    def _load(self, path: str) -> None:
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"[SQLiDetector] Model file tidak ditemukan: '{path}'"
            )

        obj = None
        last_error: Optional[Exception] = None

        # Coba load dengan joblib
        if _HAS_JOBLIB and _joblib is not None:
            try:
                obj = _joblib.load(path)
                logger.info("[SQLiDetector] Model berhasil dimuat menggunakan joblib dari '%s'", path)
            except Exception as exc:
                last_error = exc
                logger.warning(
                    "[SQLiDetector] joblib.load gagal (%s), mencoba fallback ke pickle...", exc
                )

        # Fallback ke pickle
        if obj is None:
            try:
                with open(path, "rb") as fh:
                    obj = pickle.load(fh)
                logger.info("[SQLiDetector] Model berhasil dimuat menggunakan pickle dari '%s'", path)
            except Exception as exc:
                last_error = exc
                logger.error("[SQLiDetector] pickle.load juga gagal: %s", exc)

        if obj is None:
            raise RuntimeError(
                f"[SQLiDetector] Tidak bisa memuat model dari '{path}'.\n"
                f"Error terakhir: {last_error}"
            )

        # Evaluasi format objek model
        if hasattr(obj, "named_steps"):
            self.pipeline = obj
            self._classes = getattr(obj, "classes_", None)
            logger.info("[SQLiDetector] Terdeteksi sklearn Pipeline dari '%s'", path)

        elif isinstance(obj, (tuple, list)) and len(obj) == 2:
            self.vectorizer, self.model = obj
            self._classes = getattr(self.model, "classes_", None)
            logger.info(
                "[SQLiDetector] Terdeteksi format tuple (vectorizer, model) dari '%s'", path
            )

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
                    "[SQLiDetector] Dict pickle harus berisi key model/classifier/clf/nb."
                )
            self._classes = getattr(self.model, "classes_", None)
            logger.info("[SQLiDetector] Terdeteksi format dict dari '%s'", path)

        elif hasattr(obj, "predict"):
            self.model = obj
            self._classes = getattr(obj, "classes_", None)
            logger.warning(
                "[SQLiDetector] Bare model tanpa vectorizer dimuat dari '%s'", path
            )

        else:
            raise ValueError(
                f"[SQLiDetector] Format pickle tidak dikenal: {type(obj)}."
            )

    def _vectorize(self, text: str):
        """Vectorize text using the bundled vectorizer."""
        if self.vectorizer is None:
            raise RuntimeError(
                "[SQLiDetector] Vectorizer tidak ditemukan di file model."
            )
        return self.vectorizer.transform([text])

    @staticmethod
    def _normalise_label(raw: Any) -> str:
        """Normalisasi label raw model ke 'sqli' atau 'legitimate'."""
        key = str(raw).strip().lower()
        if key in _SQLI_LABELS:
            return "sqli"
        if key in _LEGIT_LABELS:
            return "legitimate"
        try:
            return "sqli" if float(key) != 0 else "legitimate"
        except (ValueError, TypeError):
            pass
        logger.warning(
            "[SQLiDetector] Label tidak dikenal '%s', diasumsikan 'legitimate'", raw
        )
        return "legitimate"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def predict_proba_map(self, text: str) -> Dict[str, float]:
        """
        Mengembalikan dict pemetaan label kelas ke nilai probabilitas.
        Menggunakan preprocess_text sama seperti yang digunakan saat training.
        """
        # Preprocess text sebelum vectorize (konsisten dengan notebook)
        text_clean = preprocess_text(text)
        
        try:
            if self.pipeline is not None:
                raw_proba = self.pipeline.predict_proba([text_clean])[0]
                classes = getattr(self.pipeline, "classes_", range(len(raw_proba)))
            elif self.model is not None:
                X = self._vectorize(text_clean)
                raw_proba = self.model.predict_proba(X)[0]
                classes = (
                    self._classes
                    if self._classes is not None
                    else range(len(raw_proba))
                )
            else:
                raise RuntimeError("[SQLiDetector] Model belum ter-load.")
            return {str(c): float(p) for c, p in zip(classes, raw_proba)}

        except AttributeError:
            if self.pipeline is not None:
                raw_label = self.pipeline.predict([text_clean])[0]
            elif self.model is not None:
                X = self._vectorize(text_clean)
                raw_label = self.model.predict(X)[0]
            else:
                raise RuntimeError("[SQLiDetector] Model belum ter-load.")
            label = self._normalise_label(raw_label)
            return {
                "sqli": 1.0 if label == "sqli" else 0.0,
                "legitimate": 0.0 if label == "sqli" else 1.0,
            }

    def predict(self, text: str) -> Tuple[str, float, Dict[str, float]]:
        """
        Mengklasifikasikan teks dan mengembalikan 3-tuple:
        (label, confidence, proba_map)

        Menggunakan preprocess_text() konsisten dengan training pipeline.
        Ditambahkan optimalisasi cache performa tinggi untuk memangkas latensi.
        """
        # Cek Cache Terlebih Dahulu (0.00 ms Latency Hit)
        if text in self._cache:
            self._record_metric('pre_filter_ms', 0.0)
            self._record_metric('ml_ms', 0.0)
            return self._cache[text]

        t_pre_start = time.perf_counter()

        if not text or not text.strip():
            t_pre_end = time.perf_counter()
            self._record_metric('pre_filter_ms', (t_pre_end - t_pre_start) * 1000.0)
            self._record_metric('ml_ms', 0.0)
            return "legitimate", 1.0, {"legitimate": 1.0}

        # Pre-filter regex untuk string yang sangat aman
        is_safe = self.use_prefilter and _SAFE_INPUT_RE.match(text)
        t_pre_end = time.perf_counter()
        pre_filter_ms = (t_pre_end - t_pre_start) * 1000.0
        self._record_metric('pre_filter_ms', pre_filter_ms)

        if is_safe:
            self._record_metric('ml_ms', 0.0)
            result = ("legitimate", 0.95, {"0": 0.95, "1": 0.05})
            # Simpan ke cache
            if len(self._cache) < self._max_cache_size:
                self._cache[text] = result
            return result

        # Prediksi ML (dengan preprocessing text)
        t_ml_start = time.perf_counter()
        proba_map = self.predict_proba_map(text)  # preprocess_text() sudah dipanggil di sini

        raw_best = max(proba_map, key=lambda k: proba_map[k])
        confidence = proba_map[raw_best]
        label = self._normalise_label(raw_best)

        # Ambang batas deteksi
        if label == "sqli" and confidence < self.threshold:
            label = "legitimate"

        t_ml_end = time.perf_counter()
        ml_ms = (t_ml_end - t_ml_start) * 1000.0
        self._record_metric('ml_ms', ml_ms)

        result = (label, confidence, proba_map)
        
        # Simpan ke cache
        if len(self._cache) < self._max_cache_size:
            self._cache[text] = result

        return result

    def _record_metric(self, name: str, value: float) -> None:
        """Helper untuk mencatat performa ke Flask globals (g)."""
        try:
            if g:
                if not hasattr(g, 'sqli_metrics'):
                    g.sqli_metrics = {}
                g.sqli_metrics[name] = value
        except Exception:
            pass

    def is_sqli(self, text: str) -> bool:
        """Helper instan deteksi SQLi."""
        label, _, _ = self.predict(text)
        return label == "sqli"

    def __repr__(self) -> str:
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
            f"cache_size={len(self._cache)})"
        )


# ---------------------------------------------------------------------------
# Flask Middleware Factory
# ---------------------------------------------------------------------------

def register_middleware(
    app,
    detector: SQLiDetector,
    protected_endpoints: tuple[str, ...] = ("protected_login",),
    block_endpoint: str = "blocked",
) -> None:
    """
    Menambahkan hook before_request untuk validasi field POST.
    """
    @app.before_request
    def _sqli_guard():
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
                session["blocked_payload"] = value
                session["blocked_field"] = field_name
                session["blocked_confidence"] = round(confidence, 6)
                session["blocked_proba_map"] = {
                    k: round(v, 6) for k, v in proba_map.items()
                }
                return redirect(url_for(block_endpoint))

        return None

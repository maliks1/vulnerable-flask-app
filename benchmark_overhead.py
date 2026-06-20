"""
benchmark_overhead.py
---------------------
Skrip benchmark untuk mengukur 'Overhead Komputasi' yang dihasilkan oleh
middleware Naive Bayes pada aplikasi Flask.

Alur:
  1. Kirim N request HTTP normal (jinak, bukan serangan) ke Baseline (port 5001).
  2. Kirim N request identik ke Protected (port 5002).
  3. Hitung rata-rata masing-masing.
  4. Overhead = Rata-rata Protected - Rata-rata Baseline.

Cara pakai:
  python benchmark_overhead.py
"""

import statistics
import time
from typing import List

import requests

# ---------------------------------------------------------------------------
# Konfigurasi (mudah dimodifikasi)
# ---------------------------------------------------------------------------
BASELINE_URL = "http://127.0.0.1:5001/"  # Vulnerable Web App
PROTECTED_URL = "http://127.0.0.1:5002/"  # Protected Web App (Naive Bayes)

# Payload jinak (bukan serangan SQLi). Samakan untuk kedua port.
PAYLOAD = {
    "username": "admin",
    "password": "password123",
}

# Payload SQLi (untuk menguji path 403 di port 5002 dan waktu query di port 5001)
SQLI_PAYLOAD = {
    "username": "admin' OR '1'='1",
    "password": "x",
}

NUM_REQUESTS = 100
REQUEST_TIMEOUT = 10  # detik
INTERVAL_SECONDS = 1.0  # jeda antar request (rate-limit, anti-bruteforce)


# ---------------------------------------------------------------------------
# Utilitas
# ---------------------------------------------------------------------------
def measure_latency(
    url: str, payload: dict, n: int, label: str
) -> tuple[List[float], List[float]]:
    """
    Kirim n request POST ke `url` dengan `payload` yang sama,
    jeda INTERVAL_SECONDS antar request agar stabil (1 req/detik).
    Prioritas sumber latency:
      1) Header 'X-Metrics-Total-Ms' dari server (server-side, fokus utama).
      2) Fallback: round-trip time di klien (mengandung jitter jaringan).
    Kembalikan list durasi tiap request dalam milidetik (ms).
    Catatan: jeda TIDAK ikut dihitung di elapsed_ms.
    """
    latencies_ms: List[float] = []
    server_latencies_ms: List[float] = []

    # Warm-up: 1 request awal yang tidak dihitung, untuk menghindari
    # bias dari koneksi pertama / cache import.
    try:
        requests.post(url, data=payload, timeout=REQUEST_TIMEOUT).close()
    except requests.RequestException as exc:
        print(f"[WARN] Warm-up request ke {url} gagal: {exc}")

    for i in range(1, n + 1):
        start = time.perf_counter()
        try:
            resp = requests.post(url, data=payload, timeout=REQUEST_TIMEOUT)
            # Konsumsi body agar koneksi benar-benar selesai di sisi server
            # sebelum kita stop timer (mengukur full round-trip).
            resp.close()
        except requests.RequestException as exc:
            print(f"[ERROR] Request #{i} ke {url} gagal: {exc}")
            continue
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        latencies_ms.append(elapsed_ms)

        # Baca server-side latency dari header (fokus utama: input -> selesai).
        server_total = None
        try:
            raw = resp.headers.get("X-Metrics-Total-Ms")
            if raw is not None:
                server_total = float(raw)
        except (TypeError, ValueError):
            server_total = None
        if server_total is not None:
            server_latencies_ms.append(server_total)
            primary = server_total
            src = "server"
        else:
            primary = elapsed_ms
            src = "client_rtt"

        print(f"[INFO] {label} req {i}/{n} = {primary:.2f} ms (src={src})")

        # Jeda 1 detik antar request, kecuali setelah request terakhir.
        if i < n:
            time.sleep(INTERVAL_SECONDS)

    # Simpan ringkasan server-side terpisah (untuk perbandingan utama).
    if server_latencies_ms:
        print(
            f"[INFO] {label} server-side latency (X-Metrics-Total-Ms): "
            f"n={len(server_latencies_ms)}, "
            f"mean={statistics.mean(server_latencies_ms):.2f} ms"
        )
    return latencies_ms, server_latencies_ms


def summarize(label: str, latencies_ms: List[float]) -> dict:
    if not latencies_ms:
        return {
            "label": label,
            "n": 0,
            "mean": 0.0,
            "median": 0.0,
            "stdev": 0.0,
            "min": 0.0,
            "max": 0.0,
        }
    return {
        "label": label,
        "n": len(latencies_ms),
        "mean": statistics.mean(latencies_ms),
        "median": statistics.median(latencies_ms),
        "stdev": statistics.stdev(latencies_ms) if len(latencies_ms) > 1 else 0.0,
        "min": min(latencies_ms),
        "max": max(latencies_ms),
    }


def print_results(baseline: dict, protected: dict, overhead_ms: float) -> None:
    """
    Cetak hasil akhir dalam format tabel ASCII yang gampang disalin
    ke laporan skripsi.
    """
    print()
    print("=" * 72)
    print(
        " HASIL PENGUKURAN OVERHEAD KOMPUTASI MIDDLEWARE NAIVE BAYES ".center(72, "=")
    )
    print("=" * 72)
    print(f"{'Metrik':<24}{'Baseline (:5001)':>24}{'Protected (:5002)':>24}")
    print("-" * 72)
    print(f"{'Jumlah request (N)':<24}{baseline['n']:>24d}{protected['n']:>24d}")
    print(f"{'Rata-rata (ms)':<24}{baseline['mean']:>24.3f}{protected['mean']:>24.3f}")
    print(f"{'Median (ms)':<24}{baseline['median']:>24.3f}{protected['median']:>24.3f}")
    print(
        f"{'Std. Deviasi (ms)':<24}{baseline['stdev']:>24.3f}{protected['stdev']:>24.3f}"
    )
    print(f"{'Min (ms)':<24}{baseline['min']:>24.3f}{protected['min']:>24.3f}")
    print(f"{'Max (ms)':<24}{baseline['max']:>24.3f}{protected['max']:>24.3f}")
    print("-" * 72)

    # Persentase overhead (berguna untuk narasi skripsi)
    if baseline["mean"] > 0:
        overhead_pct = (overhead_ms / baseline["mean"]) * 100.0
    else:
        overhead_pct = 0.0

    print(f"{'Overhead (ms)':<24}{overhead_ms:>24.3f}")
    print(f"{'Overhead (%)':<24}{overhead_pct:>24.2f}")
    print("=" * 72)
    print()
    print("Catatan: angka di atas adalah SERVER-SIDE latency (X-Metrics-Total-Ms),")
    print("         diukur dari input masuk sampai proses server selesai")
    print("         (DB query untuk :5001, ML+abort(403) atau DB untuk :5002).")
    print("         Tidak memasukkan latensi jaringan dari sisi klien.")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    print(
        f"[INFO] Mengirim {NUM_REQUESTS} request normal ke Baseline  ({BASELINE_URL}) ..."
    )
    baseline_lat, _ = measure_latency(
        BASELINE_URL, PAYLOAD, NUM_REQUESTS, "Baseline :5001"
    )
    baseline = summarize("Baseline (:5001)", baseline_lat)

    print(
        f"[INFO] Mengirim {NUM_REQUESTS} request normal ke Protected ({PROTECTED_URL}) ..."
    )
    protected_lat, _ = measure_latency(
        PROTECTED_URL, PAYLOAD, NUM_REQUESTS, "Protected :5002"
    )
    protected = summarize("Protected (:5002)", protected_lat)

    overhead_ms = protected["mean"] - baseline["mean"]

    print_results(baseline, protected, overhead_ms)


if __name__ == "__main__":
    main()

# Vulnerable Flask App

Project ini adalah lab edukasi untuk mempelajari SQL Injection (SQLi) pada aplikasi Flask. Repository ini menyediakan dua versi aplikasi yang bisa dibandingkan langsung:

- Versi rentan (sengaja tidak aman) untuk simulasi serangan SQLi.
- Versi terlindungi dengan validasi input dan middleware deteksi SQLi berbasis machine learning.

## Daftar Isi

- [Tujuan Project](#tujuan-project)
- [Fitur Utama](#fitur-utama)
- [Spesifikasi](#spesifikasi)
- [Struktur Project](#struktur-project)
- [Cara Menjalankan](#cara-menjalankan)
- [Akun Demo](#akun-demo)
- [Daftar Endpoint](#daftar-endpoint)
- [Troubleshooting](#troubleshooting)
- [Catatan Keamanan](#catatan-keamanan)

## Tujuan Project

- Menunjukkan perbedaan perilaku login rentan vs login aman.
- Memahami dampak query SQL yang dibangun dengan string interpolation.
- Mendemonstrasikan mitigasi SQLi menggunakan parameterized query dan deteksi input mencurigakan.

## Fitur Utama

- Login rentan pada aplikasi utama.
- Login aman pada aplikasi protected.
- Middleware deteksi SQLi berbasis model Naive Bayes.
- Halaman perbandingan hasil antara mode rentan dan protected.
- Endpoint API untuk prediksi input SQLi.

## Spesifikasi

### Kebutuhan Sistem

- OS: Windows, Linux, atau macOS
- Python: disarankan versi 3.9 atau lebih baru
- Package manager: pip

### Dependensi Python

Mengacu pada file `requirements.txt`:

- Flask==2.0.1
- Werkzeug==2.0.3
- scikit-learn>=1.6.1
- joblib>=1.3.0
- numpy>=1.24.0

## Struktur Project

```text
app_protected.py
create_db.py
inspect_model.py
main.py
middleware.py
model_sqli_nb.pkl
output_file.sql
requirements.txt
static/
  css/
    style.css
templates/
  base.html
  blocked.html
  compare.html
  home.html
  login.html
  protected_login.html
```

## Cara Menjalankan

### 1. Clone dan masuk ke direktori project

```bash
git clone <url-repository>
cd Vulnerable-Flask-App
```

Jika repository sudah ada di lokal, cukup masuk ke folder project.

### 2. Buat virtual environment

```bash
python -m venv .venv
```

### 3. Aktifkan virtual environment

Windows (PowerShell):

```powershell
.\.venv\Scripts\Activate.ps1
```

Windows (CMD):

```bat
.venv\Scripts\activate.bat
```

Linux/macOS:

```bash
source .venv/bin/activate
```

### 4. Install dependensi

```bash
pip install -r requirements.txt
```

### 5. Inisialisasi database SQLite

```bash
python create_db.py
```

Perintah ini akan membuat atau memperbarui file `users.db` beserta data awal.

### 6. Jalankan aplikasi rentan

```bash
python main.py
```

Buka di browser:

```text
http://127.0.0.1:5001
```

### 7. Jalankan aplikasi protected

Di terminal lain (dengan environment aktif):

```bash
python app_protected.py
```

Buka di browser:

```text
http://127.0.0.1:5002
```

## Akun Demo

Data akun demo dibuat oleh script `create_db.py`. Contoh yang umum dipakai:

- Username: admin, Password: admin123
- Username: alice, Password: alice123

Jika login gagal, jalankan ulang:

```bash
python create_db.py
```

## Daftar Endpoint

### Aplikasi Rentan (`main.py`)

- GET `/` - menampilkan form login rentan
- POST `/` - proses login rentan
- GET `/home` - halaman dashboard setelah login

### Aplikasi Protected (`app_protected.py`)

- GET `/` - redirect ke `/protected-login`
- GET `/protected-login` - menampilkan form login aman
- POST `/protected-login` - proses login aman
- GET `/blocked` - halaman saat request diblokir middleware
- GET `/home` - dashboard protected
- GET `/compare` - halaman komparasi
- POST `/compare` - proses komparasi input
- POST `/api/predict` - prediksi input SQLi (JSON)
- POST `/logout` - keluar sesi

## Troubleshooting

- Error aktivasi PowerShell: jalankan `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned` lalu aktifkan ulang venv.
- Port sudah dipakai: ganti port pada `main.py` atau `app_protected.py`, lalu restart aplikasi.
- `model_sqli_nb.pkl` tidak ditemukan: pastikan file ada di root project.
- Database kosong/rusak: jalankan ulang `python create_db.py`.

## Catatan Keamanan

- Project ini dibuat untuk edukasi, training, dan demonstrasi.
- Jangan deploy versi rentan ke lingkungan production.
- Uji coba SQLi hanya boleh dilakukan di lingkungan lab yang Anda kendalikan.

## Lisensi

Belum ditentukan. Tambahkan file lisensi jika project akan dipublikasikan secara resmi.

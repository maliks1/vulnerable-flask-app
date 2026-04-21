# Vulnerable Flask App

Project ini adalah lab edukasi untuk mempelajari SQL injection di Flask. Repo sekarang berisi dua aplikasi yang saling membandingkan: versi rentan yang sengaja tidak aman, dan versi terlindungi yang memakai middleware deteksi SQLi berbasis Naive Bayes.

## Gambaran Umum

- `main.py` menjalankan aplikasi rentan di port `5001`.
- `app_protected.py` menjalankan aplikasi terlindungi di port `5002`.
- `create_db.py` membuat dan mengisi database SQLite `users.db`.
- `middleware.py` memuat model `model_sqli_nb.pkl` dan dipakai untuk memblokir request yang terdeteksi SQLi.
- `templates/` berisi tampilan untuk login, dashboard, blokir, dan halaman komparasi.

## Fitur

- Login rentan yang membangun query SQL dengan string interpolation.
- Login aman di aplikasi terlindungi menggunakan parameterized query.
- Middleware ML untuk mendeteksi input SQL injection sebelum request diproses.
- Halaman komparasi untuk membandingkan perilaku aplikasi rentan vs terlindungi.
- Endpoint prediksi JSON untuk demo deteksi real-time.

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
templates/
  blocked.html
  compare.html
  home.html
  login.html
  protected_login.html
```

## Persiapan

1. Buat virtual environment dan aktifkan.
2. Install dependensi.

```bash
pip install -r requirements.txt
```

3. Buat ulang database SQLite jika diperlukan.

```bash
python create_db.py
```

## Menjalankan Aplikasi

### Aplikasi Rentan

```bash
python main.py
```

Lalu buka:

```text
http://127.0.0.1:5001
```

### Aplikasi Terlindungi

```bash
python app_protected.py
```

Lalu buka:

```text
http://127.0.0.1:5002
```

## Route Utama

### `main.py`

- `GET /` dan `POST /` untuk login rentan.
- `GET /home` untuk dashboard setelah login.

### `app_protected.py`

- `GET /` mengarahkan ke `/protected-login`.
- `GET /protected-login` dan `POST /protected-login` untuk login terlindungi.
- `GET /blocked` menampilkan request yang diblokir.
- `GET /home` menampilkan dashboard terlindungi.
- `GET /compare` dan `POST /compare` untuk komparasi dua alur.
- `POST /api/predict` untuk prediksi JSON.
- `POST /logout` untuk keluar sesi.

## Database dan Data

Database yang dipakai adalah SQLite `users.db` dengan tabel `users`. Script `create_db.py` menambahkan akun contoh seperti `admin/admin123`, `alice/alice123`, dan beberapa user dummy lain untuk keperluan demo.

## Model ML

File `model_sqli_nb.pkl` adalah model deteksi SQLi yang dimuat oleh `middleware.py`. Jika ingin memeriksa format model, jalankan:

```bash
python inspect_model.py
```

## Catatan

- Project ini dibuat untuk edukasi dan demonstrasi, bukan untuk production.
- Aplikasi rentan memang sengaja tidak aman agar contoh SQL injection mudah dipelajari.
- Jika model atau database hilang, jalankan ulang `create_db.py` dan pastikan `model_sqli_nb.pkl` tetap ada di root project.

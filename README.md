# Deskripsi Proyek

Aplikasi ini adalah implementasi sederhana dari kriptografi simetris Stream XOR pada operasi CRUD berbasis Node.js + MySQL.
Data yang disimpan di database dalam bentuk ciphertext (hex).
Aplikasi menggunakan:

* SHA-256 untuk membangkitkan keystream (key + nonce + counter)

* XOR untuk proses enkripsi dan dekripsi

* MySQL sebagai penyimpanan data

* ENV untuk menyimpan key rahasia

Aplikasi ini dibuat untuk memenuhi tugas mata kuliah Kriptografi dan Steganografi.

### Cara Kerja Enkripsi

```keystreamBlock = SHA256(key + nonce + counter)```

```ciphertext = plaintext XOR keystream```

Key disimpan di .env, bukan di database.

Nonce dibuat random untuk setiap pesan.

Keystream tidak pernah disimpan, tetapi dibangkitkan ulang saat decrypt.

Tanpa key + nonce, ciphertext tidak dapat didekrip.


# Setup

1. Install package
```
npm install
```
2. Buat file _**.env**_ di root folder dan isi config dari _env_example_ sesuai config kamu

3. Jalankan Server
```
npm run server
```

# API Endpoint

## GET
```/notes/:id```

```/notes```

## POST
```/notes```

body:
```
{
  "title": "catatan 1",
  "content": "helloworld"
}
````

## PUT
```/notes/:id```

body:
```
{
  "title": "catatan 99",
  "content": "worldhello"
}
````

## POST
```/delete/:id```
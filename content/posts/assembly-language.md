---
title: Belajar Bahasa Assembly (x86/x64, Termasuk 32bit)
date: 2025-08-11
thumb: /images/cuteheker.jpeg
tags: ["Pwn"]
---

### 1. Apa itu Bahasa Assembly?

Bahasa Assembly adalah bahasa pemrograman tingkat rendah yang berhubungan langsung dengan instruksi CPU.

Bahasa ini tidak abstrak seperti Python atau C; setiap instruksi berhubungan langsung dengan operasi hardware.

Setiap baris kode Assembly diterjemahkan oleh assembler menjadi opcode biner yang dipahami CPU.

Kenapa belajar Assembly?

- Memahami cara kerja komputer di level paling dasar.
- Berguna untuk reverse engineering, optimisasi performa, dan pemrograman embedded.
- Membantu memahami sistem operasi, compiler, dan arsitektur CPU.

---

### 2. Arsitektur x86 vs x64

- **x86** → Arsitektur 32-bit (register umum: EAX, EBX, ECX, EDX, ESI, EDI, ESP, EBP).
- **x64** → Arsitektur 64-bit (register umum lebih banyak: RAX, RBX, RCX, RDX, RSI, RDI, RSP, RBP, + R8-R15).
- **32-bit vs 64-bit** → Perbedaan utamanya:
  - Ukuran register (32-bit vs 64-bit)
  - Panjang pointer (alamat memori)
  - Instruksi tambahan di x64

---

### 3. Memahami Register CPU

Register adalah ruang penyimpanan kecil di dalam CPU untuk operasi cepat.

| Register      | Ukuran        | Fungsi Utama                     | Catatan                  |
|---------------|---------------|----------------------------------|--------------------------|
| EAX / RAX     | 32 / 64-bit   | Accumulator (operasi aritmatika) | AL = 8-bit rendah        |
| EBX / RBX     | 32 / 64-bit   | Base register                    | BL = 8-bit rendah        |
| ECX / RCX     | 32 / 64-bit   | Counter untuk loop               | CL = 8-bit rendah        |
| EDX / RDX     | 32 / 64-bit   | Data register (I/O, multiplikasi)| DL = 8-bit rendah        |
| ESI / RSI     | 32 / 64-bit   | Source Index (string/memory ops) |                         |
| EDI / RDI     | 32 / 64-bit   | Destination Index                |                         |
| ESP / RSP     | 32 / 64-bit   | Stack Pointer                    | Menunjuk puncak stack    |
| EBP / RBP     | 32 / 64-bit   | Base Pointer                     | Menunjuk frame stack fungsi |

Tips mengingat:
EAX untuk hasil operasi, EBX buat backup, ECX untuk hitungan, EDX untuk data tambahan.

---

### 4. Struktur Program Assembly Dasar

Kita akan pakai NASM (Netwide Assembler) sebagai contoh.

Contoh program "Hello World" 32-bit di Linux:

```assembly
section .data
    msg db "Hello, World!", 0xA ; string + newline
    len equ $ - msg             ; panjang string

section .text
    global _start

_start:
    ; syscall write(fd=1, buf=msg, count=len)
    mov eax, 4      ; nomor syscall (write)
    mov ebx, 1      ; file descriptor (stdout)
    mov ecx, msg    ; alamat buffer
    mov edx, len    ; panjang buffer
    int 0x80        ; interrupt ke kernel

    ; syscall exit(status=0)
    mov eax, 1
    xor ebx, ebx    ; status 0
    int 0x80
```

Penjelasan baris demi baris:

1. `section .data` → Bagian data statis (string, angka).
2. `msg db "Hello, World!", 0xA` → Definisikan string + newline (0xA).
3. `len equ $ - msg` → Hitung panjang string secara otomatis.
4. `section .text` → Bagian kode program.
5. `global _start` → Entry point program.
6. `mov eax, 4` → Syscall nomor 4 = write.
7. `mov ebx, 1` → File descriptor 1 = stdout.
8. `mov ecx, msg` → Alamat buffer string.
9. `mov edx, len` → Panjang string.
10. `int 0x80` → Panggil kernel.
11. `mov eax, 1` → Syscall exit.
12. `xor ebx, ebx` → Set ebx = 0.
13. `int 0x80` → Keluar program.

---

### 5. Instruksi Dasar

#### 5.1 mov
Menyalin data dari sumber ke tujuan.

```assembly
mov eax, 5     ; eax = 5
mov ebx, eax   ; ebx = eax
```

#### 5.2 add, sub, inc, dec
```assembly
add eax, 10    ; eax = eax + 10
sub ebx, 2     ; ebx = ebx - 2
inc ecx        ; ecx = ecx + 1
dec edx        ; edx = edx - 1
```

#### 5.3 mul dan div
```assembly
mov eax, 5
mov ebx, 3
mul ebx        ; EAX = EAX * EBX
```

#### 5.4 push & pop
Digunakan untuk stack.

```assembly
push eax
pop ebx
```

---

### 6. Menggunakan Stack & Fungsi

Contoh memanggil fungsi:

```assembly
section .text
global _start

_start:
    push 5
    push 3
    call tambah
    add esp, 8  ; bersihkan argumen
    mov ebx, eax
    mov eax, 1
    int 0x80

tambah:
    mov eax, [esp+4] ; argumen pertama
    add eax, [esp+8] ; argumen kedua
    ret
```

---

### 7. Mode 32-bit vs 64-bit dalam Praktik

Di 64-bit Linux, sistem call menggunakan register berbeda (bukan int 0x80):

```assembly
mov rax, 1      ; nomor syscall write
mov rdi, 1      ; fd
mov rsi, msg    ; buffer
mov rdx, len    ; panjang
syscall
```

---

### 8. Tips Memahami Assembly Lebih Cepat

- Gunakan disassembler seperti `objdump -d` untuk melihat assembly dari program C.
- Latihan konversi kode C → Assembly.
- Eksperimen di emulator seperti DOSBox atau QEMU.

---

### 9. Loop dan Control Flow Lanjutan

Di Assembly, loop biasanya memanfaatkan register sebagai counter dan jump instructions.

#### 9.1 Loop dengan loop
```assembly
section .text
global _start

_start:
    mov ecx, 5       ; jumlah perulangan
print_loop:
    mov eax, 4
    mov ebx, 1
    mov ecx, msg
    mov edx, len
    int 0x80

    loop print_loop  ; ECX -= 1, lompat kalau != 0

    mov eax, 1
    xor ebx, ebx
    int 0x80

section .data
msg db "Halo!", 0xA
len equ $ - msg
```

#### 9.2 Conditional Jumps
Instruksi seperti:
- `je` → lompat jika equal (ZF=1)
- `jne` → lompat jika tidak equal
- `jg / jge / jl / jle` → lompat berdasarkan perbandingan signed
- `ja / jb` → untuk unsigned

Contoh:
```assembly
cmp eax, ebx
je sama
jmp selesai

sama:
    ; kode jika sama

selesai:
```

---

### 10. Manipulasi Bit

Manipulasi bit sering digunakan di optimisasi dan low-level hardware control.

Instruksi umum:
```assembly
and eax, 0xFF     ; ambil byte rendah
or eax, 0x100     ; set bit ke-8
xor eax, eax      ; reset ke 0
shl eax, 1        ; geser kiri (x2)
shr eax, 1        ; geser kanan (÷2)
```

Contoh cek bit ke-n:
```assembly
mov eax, value
bt eax, 5      ; cek bit ke-5
jc bit_set     ; lompat kalau bit 5 = 1
```

---

### 11. Interrupt Handler & System Calls

#### 11.1 int 0x80 (Linux 32-bit)
Kita sudah lihat di part 1, intinya:
- `eax` → nomor syscall
- `ebx, ecx, edx` → argumen

#### 11.2 syscall (Linux 64-bit)
Di 64-bit:
- `rax` → nomor syscall
- `rdi, rsi, rdx, r10, r8, r9` → argumen

Contoh write di 64-bit:
```assembly
mov rax, 1      ; write
mov rdi, 1      ; stdout
mov rsi, msg
mov rdx, len
syscall
```

---

### 12. SIMD: SSE & AVX

SIMD (Single Instruction Multiple Data) memungkinkan memproses banyak data sekaligus.
SSE menggunakan register XMM (128-bit), AVX menggunakan YMM (256-bit).

Contoh menambahkan 4 angka float sekaligus dengan SSE:
```assembly
movaps xmm0, [a]   ; load 4 float dari array a
movaps xmm1, [b]   ; load 4 float dari array b
addps xmm0, xmm1   ; xmm0 = xmm0 + xmm1
movaps [result], xmm0
```

---

### 13. Debugging Assembly dengan GDB

#### 13.1 Compile tanpa optimisasi
```bash
nasm -f elf32 program.asm -o program.o
ld -m elf_i386 program.o -o program
```

#### 13.2 Jalankan GDB
```bash
gdb ./program
```

#### 13.3 Perintah Penting
- `layout asm` → tampilkan assembly
- `break _start` → pasang breakpoint
- `stepi` → jalankan 1 instruksi
- `info registers` → lihat isi register
- `x/10xb $ecx` → lihat isi memori

Contoh:
```gdb
(gdb) break _start
(gdb) run
(gdb) info registers
(gdb) stepi
```

Kita bisa lihat bagaimana eax, ecx, edx berubah setiap instruksi berjalan.

---

### 14. Optimisasi Kode Assembly

#### 14.1 Menghindari Instruksi Lambat
Gunakan lea (Load Effective Address) untuk kalkulasi sederhana tanpa memori:
```assembly
lea eax, [ebx + ecx*4]
```
lebih cepat daripada mov + add berulang.

#### 14.2 Loop Unrolling
Alih-alih loop n kali, kita proses beberapa item per iterasi untuk mengurangi overhead jump.

---

### 15. Tips Mahir Assembly

1. Selalu cek manual CPU (Intel/AMD) untuk detail instruksi.
2. Latihan dengan C → disassembly untuk memahami mapping instruksi.
3. Gunakan simulator online seperti https://www.tutorialspoint.com/compile_assembly_online.php.


---
title: Apa itu CPU, memory, disk, register dalam reverse engineering (RE)
date: 2025-07-16
thumb: https://www.indiedb.com/groups/tanks/images/girls-und-panzer-gif
tags: [pwn]
---

Penjelasan sederhana tentang komponen komputer yang penting untuk dipahami dalam **reverse engineering**:

### 1. **CPU (Central Processing Unit)**  
   - **Apa itu?** "Otak" komputer yang menjalankan instruksi program.  
   - **Fungsi dalam RE**: Ketika melakukan reverse engineering, Anda menganalisis bagaimana CPU memproses instruksi dari program (misalnya, bagaimana ia menghitung, membandingkan data, atau melompat ke bagian kode tertentu).  
   - **Contoh**: Saat debugging, Anda melihat instruksi assembly yang dijalankan CPU.



#### **CPU itu seperti Koki di Dapur**  
Bayangkan:  
- **CPU** = Koki yang melakukan semua perhitungan dan perintah.  
- **Program** = Resep masakan yang harus diikuti koki.  

Ketika kamu menjalankan program (misalnya `ls` di terminal), CPU membaca instruksinya langkah demi langkah dan menjalankannya.  

---

#### **Contoh Nyata di Linux**  
Kita akan pakai perintah `strace` untuk melihat **instruksi sistem** (system calls) yang dijalankan CPU saat sebuah program berjalan.  

#### **1. Jalankan Perintah Sederhana**  
Buka terminal, lalu ketik:  
```bash
strace ls
```
Ini akan menampilkan **semua instruksi** yang CPU kerjakan saat menjalankan `ls` (contoh output):  
```plaintext
execve("/usr/bin/ls", ["ls"], 0x7ffd... /* 23 vars */)  
write(1, "file1.txt  file2.txt\n", 20)  
exit(0)
```  

#### **Apa Arti Output Ini?**  
- `execve()`: CPU memuat program `ls` ke memory.  
- `write()`: CPU menampilkan output (`file1.txt file2.txt`) ke terminal.  
- `exit()`: CPU mengakhiri program.  

**Ini adalah "bahasa CPU" tingkat dasar!**  

---

#### **2. Debugging dengan `ltrace` (Lebih Sederhana)**  
Jika `strace` terlalu rumit, coba `ltrace` untuk melihat **fungsi library** yang dipanggil:  
```bash
ltrace ls
```
Output:  
```plaintext
printf("file1.txt  file2.txt\n") = 20  
exit(0)
```  
Di sini kamu lihat CPU menjalankan `printf()` untuk menampilkan teks.  

---

#### **3. Lihat Proses CPU dengan `top`**  
Jalankan:  
```bash
top
```
Tekan **`q`** untuk keluar. Kamu akan melihat daftar program yang sedang CPU kerjakan, seperti:  
```plaintext
PID  USER    %CPU  COMMAND  
1234 user    5.0   firefox
```  
- **%CPU**: Persentase penggunaan CPU oleh program tersebut.  

---

#### **Apa Hubungannya dengan Reverse Engineering?**  
Ketika kamu reverse engineering, kamu ingin tahu:  
- **Instruksi apa** yang CPU jalankan (contoh: `strace`).  
- **Bagaimana program berinteraksi** dengan sistem (contoh: `ltrace`).  

Nanti kalau sudah terbiasa, baru masuk ke **assembly** (bahasa mesin CPU).  

---

#### **Summary untuk Pemula**  
1. CPU = "Koki" yang menjalankan perintah.  
2. Gunakan `strace`/`ltrace` untuk melihat instruksi CPU.  
3. Gunakan `top` untuk melihat beban CPU.  



## 2. **Memory (RAM - Random Access Memory)**  
   - **Apa itu?** Tempat penyimpanan sementara untuk data dan instruksi yang sedang diproses.  
   - **Fungsi dalam RE**:  
     - Menyimpan **kode program** yang sedang berjalan.  
     - Menyimpan **variabel/data** yang digunakan program.  
     - Dalam RE, Anda memeriksa isi memory untuk menemukan password, kunci enkripsi, atau memodifikasi nilai variabel.  
   - **Contoh**: Tools seperti **Cheat Engine** memanipulasi nilai di memory untuk mengubah perilaku game/program.

#### **1. Analogi Sederhana**  
- **CPU** = Koki yang memasak.  
- **RAM** = Meja tempat koki menaruh bahan & alat yang **sedang dipakai**.  
- **Hard Disk** = Lemari penyimpanan (untuk bahan yang tidak sedang dipakai).  

---

#### **2. Contoh Nyata di Linux**  

#### **a. Melihat Penggunaan RAM**  
Jalankan di terminal:  
```bash
free -h
```  
Output:  
```
              total    used    free  
Mem:           16G     5.2G    10G  
Swap:          2G      0B      2G  
```  
- **Mem**: RAM fisik (16GB total, 5.2GB dipakai).  
- **Swap**: RAM cadangan di hard disk.  

#### **b. Lihat Program yang Pakai RAM**  
```bash
top -o %MEM  # Urutkan berdasarkan penggunaan RAM
```  
Contoh output:  
```
PID  USER    %MEM  COMMAND  
1234 user    15%   chrome  
5678 user    8%    vscode  
```  
Artinya:  
- Google Chrome pakai **15% RAM**.  
- VS Code pakai **8% RAM**.  

---

#### **3. Reverse Engineering & RAM**  
Dalam RE, RAM adalah tempat kita:  
- **Mencari password** (misalnya, game menyimpan nyawa player di RAM).  
- **Memodifikasi nilai** (misalnya, mengganti "skor=100" jadi "skor=9999").  

#### **Contoh dengan `Cheat Engine` (Windows)**:  
1. Buka game (misalnya *Plants vs Zombies*).  
2. Cari nilai "sun" (misalnya 50) di RAM.  
3. Ubah jadi 9999 → Nilai di game langsung berubah!  

**Di Linux**, kita bisa pakai `scanmem` (versi sederhana Cheat Engine):  
```bash
sudo apt install scanmem  # Install dulu
scanmem /proc/[PID_game]  # Ganti [PID_game] dengan ID proses game
```  

---

#### **4. Coba Modifikasi RAM Sederhana**  
Buat program C bernama `contoh_ram.c`:  
```c
#include <stdio.h>
int main() {
    int nilai = 10;
    printf("Nilai awal: %d\n", nilai);
    printf("PID: %d\n", getpid());  // Cetak ID proses
    while (1) { }  // Program jalan terus
}
```  

**Langkah-langkah**:  
1. Kompilasi & jalankan:  
   ```bash
   gcc contoh_ram.c -o contoh_ram
   ./contoh_ram
   ```  
   Output:  
   ```  
   Nilai awal: 10  
   PID: 12345  # Catat PID ini  
   ```  

2. **Cari & Ubah Nilai di RAM** (di terminal lain):  
   ```bash
   sudo scanmem 12345  # Ganti 12345 dengan PID program
   ```  
   Di `scanmem`:  
   ```  
   > 10               # Cari nilai "10" di RAM  
   > list             # Lihat alamat memory yang menyimpan 10  
   > [alamat] 9999    # Ganti nilai di alamat itu jadi 9999  
   ```  

3. Lihat terminal program `contoh_ram` → Nilai berubah!  

---

#### **5. Visualisasi RAM dalam Program**  
```
Alamat RAM    Nilai  
0x7ffc1234    10    # Awalnya  
0x7ffc1234    9999  # Setelah dimodifikasi
```  



## 3. **Disk (Storage: HDD/SSD)**  
   - **Apa itu?** Penyimpanan permanen untuk program dan data (seperti file EXE, DLL, atau dokumen).  
   - **Fungsi dalam RE**:  
     - File di disk (misalnya, binary/executable) adalah target utama reverse engineering.  
     - Anda menganalisis bagaimana program disimpan di disk (struktur file, kode terkompilasi, dll.).  
   - **Contoh**: Tools seperti **Ghidra** atau **IDA Pro** membaca file EXE dari disk untuk dianalisis.


#### **1. Disk vs RAM: Perbedaan Krusial**
| **RAM**                          | **Disk (HDD/SSD)**                  |
|-----------------------------------|--------------------------------------|
| Penyimpanan sementara (volatile)  | Penyimpanan permanen (non-volatile)  |
| Akses cepat (CPU langsung baca)   | Akses lambat                         |
| Contoh: Variabel program          | Contoh: File EXE, DLL, dokumen       |

**Dalam RE**:  
- File di disk (seperti binary `ls` atau `chrome`) adalah target analisis.  
- Kita bisa memodifikasi file di disk untuk mengubah perilaku program.  

---

#### **2. Analisis File Binary dengan `radare2`**  
**Contoh Praktis**: Kita akan analisis binary sederhana di Linux (bisa pakai `/bin/ls` atau buat program sendiri).

#### **Langkah 1: Buat Program Sederhana**  
Buat file `contoh_disk.c`:  
```c
#include <stdio.h>
void greet() {
    printf("Password: 12345\n");  // Target kita: temukan string ini di binary!
}
int main() {
    greet();
    return 0;
}
```

Kompilasi:  
```bash
gcc contoh_disk.c -o contoh_disk
```

#### **Langkah 2: Buka Binary dengan radare2**  
```bash
r2 -AAA ./contoh_disk  # Buka file dengan analisis penuh
```

#### **Perintah Dasar radare2**  
1. **Cari Fungsi (`main` dan `greet`)**  
   ```bash
   [0x00401050]> afl            # List semua fungsi
   [0x00401050]> s main         # Pindah ke fungsi main
   [0x00401050]> pdf            # Disassemble fungsi
   ```
   Output:  
   ```asm
   ┌ 23: int main ();
   │           0x00401112      55             push rbp
   │           0x00401113      4889e5         mov rbp, rsp
   │           0x00401116      e8d5ffffff     call greet  ; Panggil fungsi greet
   │           0x0040111b      b800000000     mov eax, 0
   │           0x00401120      5d             pop rbp
   └           0x00401121      c3             ret
   ```

2. **Cari String "Password"**  
   ```bash
   [0x00401050]> iz             # List semua string di binary
   ```
   Output:  
   ```
   vaddr=0x00402004 paddr=0x00002004 ordinal=000 sz=12 len=11 section=.rodata type=ascii string=Password: 12345
   ```

3. **Lihat Isi Disk (Hex View)**  
   ```bash
   [0x00401050]> px @ 0x00402004  # Lihat data di alamat string
   ```
   Output (hexdump):  
   ```
   0x00402004  50 61 73 73 77 6f 72 64 3a 20 31 32 33 34 35 00  Password: 12345.
   ```

4. **Modifikasi Binary (Opsional)**  
   Ganti string "12345" jadi "ABCDE":  
   ```bash
   [0x00401050]> wx ABCDE @ 0x0040200B  # Overwrite di disk
   [0x00401050]> q                     # Keluar
   ```
   Jalankan program:  
   ```bash
   ./contoh_disk
   ```
   Output:  
   ```  
   Password: ABCDE  # String berhasil diubah!
   ```

---

#### **3. Visualisasi Struktur File di Disk**  
```
Binary `contoh_disk` di Disk:
┌─────────────────┐
│  Header (ELF)   │  # Informasi metadata
├─────────────────┤
│  .text          │  # Kode mesin (fungsi main, greet)
├─────────────────┤
│  .rodata        │  # String "Password: 12345"
├─────────────────┤
│  ...            │  # Section lain
└─────────────────┘
```
- **radare2** membantu melihat/memodifikasi bagian ini.

---

#### **4. Contoh Nyata: Analisis `/bin/ls`**  
```bash
r2 -AAA /bin/ls
```
- Cari fungsi `main`:  
  ```bash
  [0x00401050]> afl~main  # Cari fungsi main
  [0x00401050]> s main    # Pindah ke main
  [0x00401050]> pdf       # Disassemble
  ```
- Cari string (misalnya pesan error):  
  ```bash
  [0x00401050]> iz~cannot  # Cari string "cannot"
  ```

---

#### **5. Fungsi dalam Reverse Engineering**  
- **Menganalisis malware** (file binary mencurigakan).  
- **Memodifikasi program** (crack license, bypass auth).  
- **Memahami struktur executable** (ELF, PE).  



## 4. **Register**  
   - **Apa itu?** Penyimpanan kecil **super cepat** di dalam CPU untuk memproses data secara langsung.  
   - **Fungsi dalam RE**:  
     - Register menyimpan nilai sementara saat CPU menjalankan instruksi (misalnya, hasil perhitungan atau alamat memory).  
     - Dalam assembly/RE, Anda sering melihat register seperti:  
       - **EAX/RAX**: Menyimpan hasil operasi.  
       - **EIP/RIP**: Menunjuk ke instruksi berikutnya yang akan dijalankan.  
   - **Contoh**: Saat debugging dengan **x64dbg**, Anda memantau perubahan register untuk memahami alur program.


Bayangkan register seperti **meja kecil di depan koki** (CPU):  
- Hanya muat **sedikit data** (4-8 byte), tapi **paling cepat** diakses.  
- Dipakai untuk **operasi matematis, alamat memory, dll**.  

---

#### **1. Jenis Register Penting**  
| **Register** | **Fungsi**                                  | **Contoh (x64)** |
|--------------|--------------------------------------------|------------------|
| **RAX/EAX**  | Menyimpan **hasil operasi** (return value) | `mov eax, 5`     |
| **RIP/EIP**  | **Instruction Pointer** (alamat instruksi berikutnya) | `0x401000` |
| **RSP/ESP**  | **Stack Pointer** (alamat stack)           | `0x7fffffff`     |
| **RBX/EBX**  | Penyimpanan sementara                      | `mov ebx, eax`   |

> Catatan:  
> - `RAX` (64-bit), `EAX` (32-bit), `AX` (16-bit), `AH/AL` (8-bit).  
> - **EIP/RIP** sangat penting untuk kontrol alur program (misal: eksploitasi buffer overflow).  

---

#### **2. Contoh Nyata dengan `gdb`**  
Buat file `contoh_register.c`:  
```c
#include <stdio.h>
int main() {
    int a = 5;
    int b = 10;
    int c = a + b;  // Perhatikan register RAX/EAX!
    return 0;
}
```

#### **Langkah Debugging**  
1. Kompilasi dengan debug info:  
   ```bash
   gcc -g contoh_register.c -o contoh_register
   ```

2. Buka dengan `gdb`:  
   ```bash
   gdb ./contoh_register
   ```

3. **Set Breakpoint** dan lihat register:  
   ```bash
   (gdb) break main          # Set breakpoint di main
   (gdb) run                # Jalankan program
   (gdb) disassemble        # Lihat assembly
   (gdb) info registers     # Lihat semua register
   ```

#### **Output Assembly**  
```asm
mov    DWORD PTR [rbp-0x4], 0x5   ; a = 5
mov    DWORD PTR [rbp-0x8], 0xa   ; b = 10
mov    eax, DWORD PTR [rbp-0x4]    ; EAX = a
add    eax, DWORD PTR [rbp-0x8]    ; EAX += b (EAX = 15)
```

#### **Monitor Register**  
- Sebelum `add`, cek `eax`:  
  ```bash
  (gdb) p $eax   # Output: 5
  ```
- Setelah `add`, cek lagi:  
  ```bash
  (gdb) p $eax   # Output: 15
  ```

---

#### **3. Reverse Engineering dengan Register**  
- **Memodifikasi RIP/EIP**: Mengubah alur eksekusi program (misal: loncat ke fungsi rahasia).  
- **Membaca RAX/EAX**: Mendapatkan hasil perhitungan (misal: hasil dekripsi password).  

**Contoh Game Hacking**:  
1. Cari alamat nilai "nyawa player" di RAM.  
2. Trace instruksi yang mengubah nilai itu (misal: `sub eax, 1`).  
3. Ganti jadi `add eax, 100` untuk cheat unlimited health!  

---

#### **4. Visualisasi Register**  
```
CPU
┌─────────────┐
│  RAX = 15   │ ← Hasil a + b
│  RIP = 0x40 │ ← Alamat instruksi berikutnya
│  RSP = 0x7f │ ← Alamat stack
└─────────────┘
```

---

#### **5. Tools untuk Analisis Register**  
- **Linux**: `gdb` (dengan `info registers`).  
- **Windows**: `x64dbg`/`OllyDbg` (tampilan GUI lebih mudah).  
- **Radare2**:  
  ```bash
  r2 -d ./contoh_register
  [0x00401050]> dr   # Lihat register
  [0x00401050]> ds   # Step instruksi
  ```

---

#### **Kesimpulan**  
- **Register** adalah "tangan" CPU untuk memanipulasi data.  
- **EAX/RAX** dan **EIP/RIP** paling sering dipantau saat RE.  
- **Latihan**:  
  1. Gunakan `gdb` untuk modifikasi nilai register (`set $eax=100`).  
  2. Coba ubah **RIP** untuk loncat ke fungsi lain (advanced).  

**Tips**:  
- Pelajari **assembly dasar** (mov, add, jmp) untuk memahami register.  
- Jika bingung, ulangi contoh `gdb` di atas!  

**Next**: Gabungkan konsep CPU, RAM, Disk, dan Register untuk analisis binary lengkap! 🚀


---

### **Analog Sederhana untuk Pemula**  
Bayangkan komputer seperti **tukang masak (CPU)** yang:  
1. Mengambil resep dari buku masak (**disk**),  
2. Menyiapkan bahan di meja dapur (**RAM**),  
3. Mengolah bahan dengan tangan/alat kecil (**register**).  

Dalam **reverse engineering**, Anda adalah orang yang:  
- Membongkar resep (program) untuk melihat bagaimana ia bekerja,  
- Memodifikasi bahan (memory/register) untuk mengubah hasil masakan (perilaku program).

---

### **Penting untuk Reverse Engineering**  
- **CPU + Register**: Memahami **assembly language** (bahasa mesin) untuk melacak eksekusi program.  
- **Memory**: Mem-scan/memodifikasi nilai saat runtime (misalnya, bypassing license check).  
- **Disk**: Menganalisis file binary/executable untuk menemukan vulnerability atau algoritma.  

Mulailah dengan tools seperti **Cheat Engine** (memory editing) atau **Ghidra** (binary analysis) untuk mempraktikkan konsep ini!



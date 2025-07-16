---
title: Apa itu komputer: CPU, memory, disk, register dalam reverse engineering (RE)
date: 2025-07-16
thumb: https://www.indiedb.com/groups/tanks/images/girls-und-panzer-gif
tags: [pwn]
---


Penjelasan sederhana tentang komponen komputer yang penting untuk dipahami dalam **reverse engineering**:

### 1. **CPU (Central Processing Unit)**  
   - **Apa itu?** "Otak" komputer yang menjalankan instruksi program.  
   - **Fungsi dalam RE**: Ketika melakukan reverse engineering, Anda menganalisis bagaimana CPU memproses instruksi dari program (misalnya, bagaimana ia menghitung, membandingkan data, atau melompat ke bagian kode tertentu).  
   - **Contoh**: Saat debugging, Anda melihat instruksi assembly yang dijalankan CPU.

### 2. **Memory (RAM - Random Access Memory)**  
   - **Apa itu?** Tempat penyimpanan sementara untuk data dan instruksi yang sedang diproses.  
   - **Fungsi dalam RE**:  
     - Menyimpan **kode program** yang sedang berjalan.  
     - Menyimpan **variabel/data** yang digunakan program.  
     - Dalam RE, Anda memeriksa isi memory untuk menemukan password, kunci enkripsi, atau memodifikasi nilai variabel.  
   - **Contoh**: Tools seperti **Cheat Engine** memanipulasi nilai di memory untuk mengubah perilaku game/program.

### 3. **Disk (Storage: HDD/SSD)**  
   - **Apa itu?** Penyimpanan permanen untuk program dan data (seperti file EXE, DLL, atau dokumen).  
   - **Fungsi dalam RE**:  
     - File di disk (misalnya, binary/executable) adalah target utama reverse engineering.  
     - Anda menganalisis bagaimana program disimpan di disk (struktur file, kode terkompilasi, dll.).  
   - **Contoh**: Tools seperti **Ghidra** atau **IDA Pro** membaca file EXE dari disk untuk dianalisis.

### 4. **Register**  
   - **Apa itu?** Penyimpanan kecil **super cepat** di dalam CPU untuk memproses data secara langsung.  
   - **Fungsi dalam RE**:  
     - Register menyimpan nilai sementara saat CPU menjalankan instruksi (misalnya, hasil perhitungan atau alamat memory).  
     - Dalam assembly/RE, Anda sering melihat register seperti:  
       - **EAX/RAX**: Menyimpan hasil operasi.  
       - **EIP/RIP**: Menunjuk ke instruksi berikutnya yang akan dijalankan.  
   - **Contoh**: Saat debugging dengan **x64dbg**, Anda memantau perubahan register untuk memahami alur program.

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

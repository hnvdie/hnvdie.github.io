---
title: Belajar Binary Exploitation (PWN) dari Nol - Exploit Development
date: 2025-08-11
thumb: /images/cuteheker.jpeg
tags: ["Pwn"]
---


{{< raw >}}
<img src="https://ibb.co.com/FqgzqDDZ"><img src="https://i.ibb.co.com/x8J68779/images-1.jpg">
{{< /raw >}}

<br>
<br>

**"Gw mau belajar PWN / binary exploitation, tapi bingung mulai dari mana!"**  

Kalimat di atas adalah masalah klasik pemula. Banyak yang langsung nyemplung ke buffer overflow tanpa paham dasar, lalu frustasi dan menyerah.  

Artikel ini **beda**—kita akan **breakdown langkah-langkah konkret**, termasuk:  
✔ **Apa yang harus dipelajari di setiap tahap?**  
✔ **Berapa dalam harus menguasainya?**  
✔ **Kapan bisa lanjut ke tahap selanjutnya?**  
✔ **Contoh kasus nyata untuk pemula.**  

Tujuannya: **Kamu bisa langsung praktik eksploitasi, bukan sekadar teori!**  

---

## **🔥 Stage 0 – Mental Model Sebelum Belajar PWN**  
**"Kenapa banyak orang gagal sebelum mencoba exploit pertama?"**  
Karena mereka:  
❌ Langsung loncat ke **heap exploit** tanpa paham stack.  
❌ Tidak tahu **batasan belajar C/ASM** (harus sejauh apa?).  
❌ Tidak punya **contoh eksploitasi sederhana** untuk motivasi.  

**Solusinya:**  
1. **Jangan langsung belajar semuanya!** PWN itu seperti belajar renang—mulai dari kolam dangkal (stack overflow) dulu.  
2. **Cukup pahami dasar yang relevan** (tidak perlu jadi expert C/ASM dulu).  
3. **Praktik langsung** dengan challenge mudah (lihat **contoh kasus** di bawah).  

---

## **📍 Stage 1 – Dasar Wajib (Bukan Teori Sembarangan!)**  
**Tujuan:** Bisa baca kode C & pahami bagaimana program dijalankan di memori.  

### **1. Pemrograman C (Versi PWN, Bukan Sekadar Hello World!)**  
**Yang wajib dipahami:**  
- **Pointer & Memory**  
  ```c
  int x = 5;  
  int *ptr = &x;  // ptr menyimpan alamat memori x
  printf("%p", ptr); // Cetak alamat memori
  ```  
  **Kenapa ini penting?** Karena exploitasi sering manipulasi alamat memori!  

- **Array & Buffer Overflow Sederhana**  
  ```c
  char buf[10];
  scanf("%s", buf); // Apa yang terjadi jika input > 10 karakter?
  ```  
  **Ini dasar buffer overflow!**  

- **Fungsi & Stack Frame**  
  ```c
  void vuln() {
      char buf[10];
      gets(buf); // Danger! Tidak ada batasan input
  }
  ```  
  **Ini akan dipakai di exploit pertama kamu!**  

📌 **Berhenti belajar C di sini jika tujuan awal cuma PWN dasar!**  
✅ **Udah cukup?** Jika kamu paham contoh di atas, lanjut!  
📚 **Resource:** [C Programming for PWN (Mini Guide)](https://www.learn-c.org/)  

---

### **2. Dasar Assembly (x64) – Hanya yang Penting untuk PWN!**  
**Jangan belajar semuanya!** Fokus ke:  
- **Register penting:**  
  - `RIP` (Instruction Pointer) → Alamat eksekusi berikutnya.  
  - `RSP` (Stack Pointer) → Alamat stack.  
  - `RAX` (Return Value) → Nilai balik fungsi.  

- **Instruksi dasar:**  
  ```asm
  mov rax, rbx  ; Salin nilai RBX ke RAX
  push rax      ; Simpan RAX ke stack
  pop rbx       ; Ambil nilai dari stack ke RBX
  call func     ; Panggil fungsi
  ret           ; Kembali dari fungsi
  ```  
**Kenapa ini cukup?** Karena kebanyakan eksploitasi hanya butuh baca disassembly, bukan nulis ASM dari nol.  

📌 **Udah paham?** Jika bisa baca kode ASM sederhana, lanjut!  

---

### **3. Memory Layout Program (Praktis!)**  
**Lihat langsung di GDB:**  
```bash
gdb ./program
(gdb) info proc mappings  # Liat layout memori program
```  
Contoh output:  
```
0x400000 0x401000 r-x (Text Segment, kode program)
0x7fffffff0000 0x7fffffff1000 rw- (Stack)
```  
**Poin penting:**  
- **Stack** → Lokal variabel, return address (target exploitasi).  
- **Heap** → Memory dinamis (malloc/free).  
- **Text** → Kode program (biasanya read-only).  

✅ **Kamu siap lanjut jika:**  
- Bisa baca kode C sederhana.  
- Paham konsep stack & buffer overflow.  
- Baca ASM dasar (mov, push, call).  

---

## **📍 Stage 2 – Tools & Exploit Pertama (Langsung Praktik!)**  
**Tujuan:** Langsung coba exploit pertama dalam 1 jam!  

### **1. Setup Tools Wajib**  
- **GDB + pwndbg** → Debugging.  
  ```bash
  sudo apt install gdb
  git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh
  ```  
- **pwntools** → Library Python untuk exploit.  
  ```bash
  pip install pwntools
  ```  

### **2. Contoh Exploit Pertama (Buffer Overflow Sederhana)**  
**Program vulnerable (`vuln.c`):**  
```c
#include <stdio.h>
void vuln() {
    char buf[10];
    gets(buf); // Tidak ada batasan input!
}
int main() {
    vuln();
}
```  
**Compile:**  
```bash
gcc vuln.c -o vuln -fno-stack-protector -no-pie
```  

**Exploit (`exploit.py`):**  
```python
from pwn import *
p = process("./vuln")
payload = b"A" * 20 + p64(0xdeadbeef)  # Overwrite return address
p.sendline(payload)
p.interactive()
```  
**Apa yang terjadi?**  
1. Input `"A"*20` memenuhi buffer + EBP.  
2. `p64(0xdeadbeef)` timpa return address.  
3. Program crash karena mencoba eksekusi di `0xdeadbeef`.  

📌 **Ini adalah exploit pertama kamu!**  

---

## **📍 Stage 3 – Roadmap Lanjutan (Setelah Bisa Exploit Sederhana)**  
Setelah paham Stage 1 & 2, baru pelajari:  

### **1. Format String Bug**  
```c
printf(user_input); // Jika user bisa kontrol input
```  
**Eksploitasi:**  
- Baca memori (`%x`).  
- Tulis ke memori (`%n`).  

### **2. Return-Oriented Programming (ROP)**  
- **Konsep:** Gabungkan potongan kode (`gadget`) untuk bypass NX.  
- **Contoh:** `pop rdi; ret` untuk set argument fungsi.  

### **3. Heap Exploitation**  
- **Pelajari setelah stack lancar!**  
- Contoh: Use-After-Free (UAF), tcache poisoning.  

---

## **💡 Tips Anti-Frustasi**  
✔ **Jangan belajar semuanya sekaligus!** Fokus 1 vulnerability dulu (stack overflow).  
✔ **Lihat writeup jika stuck** (LiveOverflow, Pwn College).  
✔ **Gunakan cheat sheet** (ctf101.org).  

🚀 **Sekarang kamu punya peta belajar yang jelas! Mulai hari ini dan happy hacking!**  

**Contoh challenge pemula:**  
- [picoCTF](https://picoctf.org/) (cari "buffer overflow").  
- [Protostar (Stack)](https://exploit-exercises.com/protostar/).  

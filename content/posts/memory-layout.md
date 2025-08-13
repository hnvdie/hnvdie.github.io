---
title: Memahami Stack Frame dan Memory Layout - pwn02
date: 2025-08-13
thumb: /images/cuteheker.jpeg
tags: ["Pwn"]
---

Dalam binary exploitation, memahami struktur stack frame dan memory layout adalah fundamental. Artikel ini akan menjelaskan secara step-by-step bagaimana stack bekerja, cara membaca memory dengan `pwndbg`, dan visualisasi yang mudah dipahami. Kita mulai dari layout memory, penggunaan `pwndbg`, parsing stack, hingga cara membacanya untuk keperluan binary exploitation.

---

## **1. Layout Memory dan Stack Frame**

![Main Frame](/images/memory-layout0.webp)

Stack adalah struktur data LIFO (Last In, First Out) yang digunakan untuk menyimpan data sementara, seperti variabel lokal, return address, dan saved base pointer. Berikut tahapan pembentukan stack frame:

### **1️⃣ Sebelum Masuk Fungsi (Baru Call Main)**

![Flow](/images/memory-layout1.webp)

Saat fungsi dipanggil (misal `call main`), beberapa hal terjadi:
- **Return Address** disimpan di stack (untuk kembali setelah fungsi selesai).
- **RBP lama** (base pointer fungsi sebelumnya) akan disimpan.

```
[ High Address ]
| Argumen fungsi lama            |
| Return Address                  | ← call simpan ini
| RBP lama (Base Pointer Old)     | ← punya fungsi sebelumnya
[ Low Address ]  
```
- **RSP** (Stack Pointer) menunjuk ke **RBP lama**.
- Belum ada stack frame baru.

![Flow](/images/memory-layout2.webp)

---

### **2️⃣ Setelah `push rbp; mov rbp, rsp`**
Instruksi ini membentuk stack frame baru:
1. `push rbp` → Simpan RBP lama ke stack.
2. `mov rbp, rsp` → RBP baru = RSP saat ini.

```
[ High Address ]
| Argumen fungsi lama             |
| Return Address                   |
| RBP lama (Base Pointer Old)      | ← disimpan oleh `push rbp`
RBP → posisi ini
[ Low Address ]
```
- **RBP** sekarang menunjuk ke lokasi ini (base frame baru).
- **RSP = RBP** (belum ada variabel lokal).

---

### **3️⃣ Setelah Alokasi Variabel Lokal (`sub rsp, X`)**
Untuk variabel lokal (misal `int x;`), stack dialokasikan dengan `sub rsp, 0x20` (misal 32 byte).

```
[ High Address ]
| Argumen fungsi lama             |
| Return Address                   |
| RBP lama (Base Pointer Old)      | ← dari `push rbp`
RBP → posisi ini
| Variabel lokal (int x; int b; …) |
| Data sementara                   |
RSP → posisi terendah frame sekarang
[ Low Address ]
```
- **RSP** turun untuk memberi ruang variabel lokal.
- **RBP** tetap di tempat, memudahkan akses argumen & variabel.

---

## **2. Contoh Nyata dengan `pwndbg`**
Misal kita memiliki kode assembly:
```
push   rbp
mov    rbp, rsp
sub    rsp, 0x20
```

### **Nilai Register Sebelum & Sesudah `sub rsp, 0x20`**
| Register | Sebelum (`mov rbp, rsp`) | Sesudah (`sub rsp, 0x20`) |
|----------|--------------------------|---------------------------|
| **RBP**  | `0x7fffffffda00`         | `0x7fffffffda00` (tetap)  |
| **RSP**  | `0x7fffffffda00`         | `0x7fffffffd9e0`          |

**Perhitungan:**
```
RSP baru = RSP lama - 0x20  
         = 0x7fffffffda00 - 0x20  
         = 0x7fffffffd9e0
```

---

## **3. Chain Stack Frame (Linked List RBP)**
Dalam debugging, kita sering melihat struktur seperti:
```
RBP => 0x7fffffffda00 → 0x7fffffffdaa0 → 0x7fffffffdb00 → ...
```
Ini adalah **linked list stack frame**:
- Setiap `RBP` menyimpan **RBP fungsi sebelumnya**.
- Berguna untuk **stack unwinding** (kembali ke fungsi pemanggil).

### **Visualisasi Stack Frame**
```
Higher Address
┌─────────────────┐
│ ...             │
├─────────────────┤
│ RBP = 0x7fffffffdb00 │ ← Frame sebelum `main` (libc)
├─────────────────┤
│ ...             │
├─────────────────┤
│ RBP = 0x7fffffffdaa0 │ ← Frame pemanggil `main` (misal `_start`)
├─────────────────┤
│ ...             │
├─────────────────┤
│ RBP = 0x7fffffffda00 │ ← Frame `main` (saat ini)
├─────────────────┤
│ Local Variables │ (RSP = 0x7fffffffd9e0)
└─────────────────┘
Lower Address
```

### **Mekanisme Return dari Fungsi**
Saat fungsi selesai, instruksi `leave` dan `ret` bekerja:
```
leave      ; setara dengan: mov rsp, rbp; pop rbp
ret        ; pop return address dan jump ke sana
```
- **`leave`** mengembalikan `RSP` dan `RBP` ke keadaan semula.
- **`ret`** kembali ke caller menggunakan return address.

---

## **4. Tips Cepat Mengingat Stack Frame**
- **`push rbp`** → Simpan patokan lama (RBP fungsi sebelumnya).
- **`mov rbp, rsp`** → Pasang patokan baru (RBP = RSP saat ini).
- **`sub rsp, X`** → Alokasi ruang untuk variabel lokal.

> 💡 **Patokan = Base Pointer (RBP)**  
> **Posisi Sekarang = Stack Pointer (RSP)**

---

## **5. Aplikasi dalam Binary Exploitation**
Dengan memahami stack frame, kita bisa:
1. **Buffer Overflow** → Timpa return address untuk kontrol alur program.
2. **ROP Chaining** → Manfaatkan saved RBP dan return address untuk eksekusi kode.
3. **Memory Leak** → Baca nilai stack untuk bypass ASLR.

---

## **Kesimpulan**
- **Stack frame** adalah struktur fundamental dalam eksekusi program.
- **RBP** = Base Pointer (patokan stack frame saat ini).
- **RSP** = Stack Pointer (posisi terakhir di stack).
- **Chain RBP** membentuk linked list untuk kembali ke fungsi sebelumnya.
- **Pemahaman stack** penting untuk binary exploitation.

1️⃣ Sebelum masuk fungsi (baru call main)

[ High Address ]
| Argumen fungsi lama            |
| Return Address                  | ← call simpan ini
| RBP lama (Base Pointer Old)     | ← punya fungsi sebelumnya
[ Low Address ]

Belum ada stack frame baru.

RSP → menunjuk ke RBP lama.



---

2️⃣ Setelah push rbp; mov rbp, rsp

[ High Address ]
| Argumen fungsi lama             |
| Return Address                   |
| RBP lama (Base Pointer Old)      | ← disimpan lagi oleh push rbp
RBP → posisi ini
[ Low Address ]

RBP baru dipatok di sini.

RSP = RBP (belum ada variabel lokal).



---

3️⃣ Setelah bikin variabel lokal

[ High Address ]
| Argumen fungsi lama             |
| Return Address                   |
| RBP lama (Base Pointer Old)      | ← dari push rbp
RBP → posisi ini
| Variabel lokal (int x; int b; …) |
| Data sementara                   |
RSP → posisi terendah frame sekarang
[ Low Address ]

RSP turun untuk memberi ruang ke variabel lokal.

RBP tetap di tempat, jadi gampang akses argumen & variabel.




---


Pada instruksi `sub rsp, 0x20`, nilai RSP sebelum dan sesudah instruksi adalah sebagai berikut:

**Sebelum `sub rsp, 0x20`:**
- RSP = `0x7fffffffda00` (nilai ini sama dengan nilai RBP karena sebelumnya ada instruksi `mov rbp, rsp`)

**Sesudah `sub rsp, 0x20`:**
- RSP = `0x7fffffffda00 - 0x20 = 0x7fffffffd9e0`

Jadi:
- **Sebelum:** `RSP = 0x7fffffffda00`
- **Sesudah:** `RSP = 0x7fffffffd9e0`

Ini adalah alokasi space di stack sebesar `0x20` (32 bytes) untuk keperluan local variables atau penyimpanan data lainnya dalam fungsi `main`.


Nilai `0x7fffffffdb00` adalah alamat memory yang ditunjuk oleh RBP dalam rantai stack frame (stack frame chain).  

### Penjelasan Konteks:
Dari informasi yang diberikan:  
```
RBP => 0x7fffffffda00 —▸ 0x7fffffffdaa0 —▸ 0x7fffffffdb00 ◂— ...
```
Ini menunjukkan linked list dari **stack frame** (bingkai stack) dalam program.  

- **`RBP` saat ini** = `0x7fffffffda00` (base pointer untuk fungsi `main`).  
- **Nilai yang disimpan di `[RBP]`** = `0x7fffffffdaa0` (ini adalah RBP dari fungsi pemanggil/parent frame).  
- **Nilai yang disimpan di `[0x7fffffffdaa0]`** = `0x7fffffffdb00` (RBP dari fungsi sebelumnya lagi).  

### Arti `0x7fffffffdb00`:
Ini adalah **saved RBP** (RBP yang disimpan) dari stack frame **sebelum fungsi `main`**, biasanya:  
- **`_start` atau `__libc_start_main`** (fungsi awal yang mempersiapkan eksekusi program).  
- Nilai ini adalah bagian dari mekanisme **stack unwinding** (untuk kembali ke fungsi pemanggil).  

### Visualisasi Stack:
```
Higher Address  
┌─────────────────┐  
│ ...             │  
├─────────────────┤  
│ RBP = 0x7fffffffdb00 │  ← Frame sebelum main  
├─────────────────┤  
│ ...             │  
├─────────────────┤  
│ RBP = 0x7fffffffdaa0 │  ← Frame pemanggil main  
├─────────────────┤  
│ ...             │  
├─────────────────┤  
│ RBP = 0x7fffffffda00 │  ← Frame main (saat ini)  
├─────────────────┤  
│ Local Variables │  (RSP = 0x7fffffffd9e0)  
└─────────────────┘  
Lower Address  
```

### Kesimpulan:
- `0x7fffffffdb00` adalah **saved RBP** dari stack frame sebelumnya (fungsi yang memanggil `main`).  
- Ini membantu program untuk kembali ke fungsi pemanggil setelah `main` selesai (dengan instruksi `leave` atau `pop rbp`).  

Jika Anda sedang men-debug, nilai ini biasanya tidak perlu dimodifikasi kecuali Anda melakukan exploitasi stack.

Mari kita breakdown alur stack frame-nya step by step biar jelas.  

### **1. Konteks Saat Ini (Di Fungsi `main`)**
- **`RBP` saat ini** = `0x7fffffffda00` (base pointer fungsi `main`).  
- **`RSP` saat ini** = `0x7fffffffd9e0` (setelah `sub rsp, 0x20`).  
- **Isi memory di `[RBP]`** = `0x7fffffffdaa0` (nilai saved RBP dari fungsi pemanggil).  

### **2. Alur Stack Frame (Chain of Saved RBP)**
```
Higher Address (Previous Stack Frames)
│
├─ 0x7fffffffdb00  → RBP dari fungsi sebelum main (misal: `__libc_start_main`)
│
├─ 0x7fffffffdaa0  → RBP dari fungsi yang memanggil `main` (misal: `_start` atau caller sebelum main)
│
├─ 0x7fffffffda00  → RBP saat ini (fungsi `main`)  
│   ├─ Local variables (RSP = 0x7fffffffd9e0)  
│   └─ ...  
│
└─ Lower Address (Stack grows downward)
```

### **3. Mekanisme `RBP` dan `RSP`**
- **`RBP` (Base Pointer)** = Menunjuk ke **awal stack frame saat ini**.  
  - Nilai `[RBP]` = **Saved RBP** (RBP fungsi sebelumnya).  
  - `[RBP + 8]` = Return Address (alamat kembali setelah fungsi selesai).  
- **`RSP` (Stack Pointer)** = Menunjuk ke **top of stack** (data terakhir yang di-push).  

### **4. Flow Eksekusi**
1. **Sebelum `main` dipanggil**:  
   - Ada fungsi sebelumnya (misal `_start`) yang punya `RBP = 0x7fffffffdaa0`.  
   - Saat memanggil `main`, `RBP` lama (`0x7fffffffdaa0`) di-push ke stack.  

2. **Di awal `main` (setelah `push rbp` dan `mov rbp, rsp`)**:  
   - `RBP` baru = `0x7fffffffda00` (stack frame baru untuk `main`).  
   - `[RBP]` (isi memory di `0x7fffffffda00`) = `0x7fffffffdaa0` (RBP sebelumnya).  

3. **Setelah `sub rsp, 0x20`**:  
   - `RSP` turun `0x20` (32 byte) → `RSP = 0x7fffffffd9e0`.  
   - Ini mengalokasikan space untuk **local variables**.  

4. **Jika `main` selesai (return)**:  
   - CPU akan pakai `RBP` untuk restore stack frame sebelumnya:  
     ```asm
     leave          ; mov rsp, rbp; pop rbp (RBP kembali ke 0x7fffffffdaa0)
     ret            ; kembali ke caller
     ```

### **5. Nilai-Nilai Penting**
| Register/Address | Nilai | Keterangan |
|------------------|-------|------------|
| **`RBP` saat ini** | `0x7fffffffda00` | Base pointer fungsi `main`. |
| **`[RBP]`** | `0x7fffffffdaa0` | Saved RBP (fungsi sebelum `main`). |
| **`[0x7fffffffdaa0]`** | `0x7fffffffdb00` | Saved RBP (fungsi sebelum `_start`/libc). |
| **`RSP` setelah `sub rsp, 0x20`** | `0x7fffffffd9e0` | Top of stack (untuk local variables). |

### **6. Kesimpulan**
- **RBP selalu merujuk ke saved RBP sebelumnya** → Membentuk linked list stack frame.  
- **RSP menunjuk ke ujung stack** (tempat data/local variables disimpan).  
- **`0x7fffffffdb00` adalah RBP dari fungsi sebelum `main`**, biasanya bagian dari inisialisasi program oleh libc.  

Jika ada yang masih kurang jelas, bisa ditanyakan!


---

catatan: `patokan`: "Alamat Address"

push rbp → “Simpan patokan lama ke stack”
(nyimpen base pointer lama ke tumpukan)

mov rbp, rsp → “Tetapkan patokan baru di posisi stack sekarang”
(ngambil alamat stack pointer saat ini, lalu jadikan itu base pointer baru)



---

💡 Jadi kalau lo mau ingat cepat:

push rbp      ; simpan patokan lama
mov rbp, rsp  ; pasang patokan baru

Patokan = base pointer (RBP)
Posisi sekarang = stack pointer (RSP)


---

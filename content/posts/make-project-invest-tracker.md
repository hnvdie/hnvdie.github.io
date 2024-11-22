---
title: Membuat Program Pengingat Investasi Crypto Sederhana Dengan Python
date: 2024-11-22
tags: ["projects"]
---

![pic](/images/ghostecho.jpg)

GhostNet adalah sebuah alat pengelola investasi crypto yang saya buat untuk membantu kamu dalam melacak nilai investasi dan return dari berbagai mata uang kripto. Dengan antarmuka yang sederhana, program ini dapat membantu kamu mengatur dan memantau aset crypto dengan lebih terstruktur.

## Fitur Utama

- **Tambah Investasi & Return**: Menambahkan nilai investasi dan return untuk setiap mata uang kripto yang kamu pilih.
- **Edit Data**: Mengubah data investasi dan return jika terjadi perubahan nilai.
- **Hapus Data**: Menghapus data untuk mata uang kripto yang sudah tidak kamu perhatikan.
- **Statistik Lengkap**: Menampilkan total investasi, return, serta keuntungan atau kerugian secara keseluruhan.
- **Desain Sederhana**: Tampilan yang bersih dan mudah dipahami, cocok untuk pengguna pemula hingga yang sudah berpengalaman.

## Penjelasan Kode Program

Di bawah ini adalah penjelasan mengenai bagian-bagian kode **GhostNet** yang saya buat, serta bagaimana setiap fungsi berperan dalam program.

### 1. **Fungsi `read_data`**

Fungsi ini digunakan untuk membaca file yang berisi data investasi dan return. Jika file tidak ditemukan, maka fungsi ini akan membuat file baru dengan header yang sudah ditentukan.

```python
def read_data(filename):
    data = {}
    if not os.path.exists(filename):
        with open(filename, 'w') as f:
            f.write("@ currency, invest, return\n")  # Header file
        print(f"info: create new {filename}")
    else:
        with open(filename, 'r') as f:
            lines = f.readlines()[1:]  # Skip header line
            for line in lines:
                parts = line.strip().split(', ')
                if len(parts) == 3:
                    currency = parts[0].strip().lower()
                    invest = int(parts[1])
                    return_value = int(parts[2])
                    data[currency] = {'invest': invest, 'return': return_value}
    return data
```

2. Fungsi write_data

Fungsi ini digunakan untuk menulis data ke dalam file setelah terjadi perubahan, seperti menambah atau mengedit nilai investasi dan return.
```python
def write_data(filename, data):
    with open(filename, 'w') as f:
        f.write("@ currency, invest, return\n")  # Header file
        for currency, values in data.items():
            f.write(f"{currency.upper()}, {values['invest']}, {values['return']}\n")
```
3. Fungsi add_investment

Fungsi ini digunakan untuk menambah jumlah investasi pada mata uang kripto tertentu. Jika mata uang belum ada dalam data, fungsi ini akan menambahkannya.

```python
def add_investment(data, currency, invest_amount):
    currency = currency.lower()
    if currency in data:
        data[currency]['invest'] += invest_amount
    else:
        data[currency] = {'invest': invest_amount, 'return': 0}
    print(f"Investment added: {currency.upper()} with {format_currency(invest_amount)}")
```

4. Fungsi add_return

Fungsi ini digunakan untuk menambahkan return yang diperoleh dari investasi pada mata uang kripto tertentu.
```python
def add_return(data, currency, return_amount):
    currency = currency.lower()
    if currency in data:
        data[currency]['return'] += return_amount
    else:
        data[currency] = {'invest': 0, 'return': return_amount}
    print(f"Return added: {currency.upper()} with {format_currency(return_amount)}")
```
5. Fungsi edit_data

Fungsi ini memungkinkan kamu untuk mengubah nilai investasi dan return dari mata uang kripto yang ada.

```python
def edit_data(data, currency, invest=None, return_value=None):
    currency = currency.lower()
    if currency in data:
        if invest is not None:
            data[currency]['invest'] = invest
        if return_value is not None:
            data[currency]['return'] = return_value
        print(f"Data edited for {currency.upper()}")
    else:
        print(f"Currency {currency} not found.")
```

6. Fungsi delete_data

Fungsi ini digunakan untuk menghapus data untuk mata uang yang sudah tidak lagi kamu perhatikan. Fungsi ini menjaga agar data tetap terorganisir.

```python
def delete_data(data, currency):
    currency = currency.lower()
    if currency in data:
        del data[currency]
        print(f"{currency.upper()} data has been deleted.")
    else:
        print(f"Currency {currency} not found.")

```

7. Fungsi display_statistics

Fungsi ini akan menampilkan statistik total investasi, return, serta keuntungan atau kerugian dari seluruh data mata uang kripto yang tercatat.

```python
def display_statistics(data):
    total_investment = sum([values['invest'] for values in data.values()])
    total_return = sum([values['return'] for values in data.values()])
    total_profit_loss = total_return - total_investment
    print("-"*100)
    print("Statistics:")
    print(f"Total Investment: {format_currency(total_investment)}")
    print(f"Total Return: {format_currency(total_return)}")
    print(f"Total Profit/Loss: {format_currency(total_profit_loss)}")
    print("\nCurrency Breakdown:")
    for currency, values in data.items():
        print(f"{currency.upper()}: Invest = {format_currency(values['invest'])}, Return = {format_currency(values['return'])}")
    print("-"*100)
    print()
```

8. Fungsi format_currency

Fungsi ini digunakan untuk memformat nilai investasi atau return menjadi lebih mudah dibaca, dengan menambahkan simbol mata uang dan memisahkan angka dengan titik.

```python
def format_currency(amount, symbol="USD"):
    return f"{symbol} {amount:,}".replace(",", ".")
```
## Cara Penggunaan

1. Menambahkan Investasi
Kamu bisa menambahkan investasi dengan memilih menu "Tambah Investasi" dan memasukkan jumlah dana yang kamu investasikan dalam mata uang crypto pilihanmu.


2. Menambahkan Return
Untuk menambah return, pilih menu "Tambah Return" dan masukkan jumlah return yang kamu peroleh.


3. Mengedit Data
Jika ada perubahan, misalnya karena investasi atau return berubah, kamu bisa mengeditnya melalui menu "Edit Data".


4. Menghapus Data
Jika ada mata uang kripto yang sudah tidak kamu perhatikan, kamu bisa menghapusnya dengan memilih "Hapus Data".


5. Melihat Statistik
Menu "Statistik" akan menunjukkan gambaran umum tentang total investasi, return, serta profit atau kerugian yang kamu peroleh.



## Pengembangan Lebih Lanjut

Program ini masih dapat dikembangkan lebih lanjut, seperti penambahan fitur-fitur baru, integrasi dengan API untuk mengupdate data harga cryptocurrency secara otomatis, dan lainnya.

Kamu bisa mengakses GhostNet di [Github](https://github.com/hnvdie/ghostnet).


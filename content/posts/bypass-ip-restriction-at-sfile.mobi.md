---
title: Bypass IP restriction at sfile.mobi - writeup
date: 2022-08-27
thumb: https://www.indiedb.com/groups/tanks/images/girls-und-panzer-gif
tags: [writeups]
---

{{< raw >}}
<a href="https://www.indiedb.com/groups/tanks/images/girls-und-panzer-gif" title="Girls und Panzer GIF - Indie DB" target="_blank"><img src="https://media.indiedb.com/cache/images/groups/1/3/2074/thumb_620x2000/maus_gif.gif" alt="Girls und Panzer GIF" /></a>
{{< /raw >}}
write up sederhana tentang bagaimana saya bisa menemukan bug IP restriction bypass di situs sfile.mobi.

dan mendapatkan reward yang lumayan, hanya karena laporan bug sepele ini.

### FYI (For you information)

jadi sebelumnya saya menemukan data leakage dari salah satu website yang tidak bisa saya sebutkan. karena ini privasi web diluar sfile.mobi. yang mana
data tersebut berisi informasi seperti username, password dan email. dikarenakan situs yang terdapat data leakage tersebut adalah situs yang memiliki latar belakang seperti sfile.mobi juga. yaitu service **free file sharing service**. jadinya saya mempunyai ide yang cukup cemerlang.

karena saya sering mengunjungi situs sfile.mobi buat download config :/<
terlintas dalam pikiran saya.

"*apa para pengguna didata yang saya miliki ini, juga login disitus sfile.mobi?*"

dan yap tercetus lah ide untuk melakukan brute-forcing.

# Proof OF Concept 

awalnya saya mencoba mengunjungi halaman sfile.mobi dan ke halaman loginnya untuk melakukan web scraping.
yang URL nya berada disini. 

`https://sfile.mobi/login.php`

dengan tujuan membuat tool atau bot otomatisasi login dengan ribuan data yang saya punya
diatas tadi. awalnya saya hanya menulis program sederhana untuk mencobanya. dan ini hasil yang
saya temukan.

{{< raw >}}
<img src="/images/pp1.jpg" >
source code: <a href=" https://pastebin.com/raw/Kg3p0XKx">pastebin</a>
{{< /raw >}}

terlihat disana menunjukan status kode 401 dan programnya crash (stuck) tidak jalan lagi.
dikarenakan halaman loginnya sudah tidak bisa diakses atau terkena limit IP.
sama hal ketika saya kunjungi melalui browser, IP saya pun sudah terbanned.


{{< raw >}}
<img src="/images/pp2.jpg" >
{{< /raw >}}


lantas saya mencoba alternatif lain untuk melakukan brute-force tanpa harus terkena limit IP.

yang pertama saya mencoba dengan proxy namun tetap saja gagal, tidak bisa ditembus.
langkah kedua saya mencoba melakukan injeksi terhadap headers ketika melakukan POST
request.yaitu melakukan bypass IP source restrictions dengan HTTP headers.

disini saya hanya memodifikasi header nya dengan menambahkan nilai.
```shell
"X-Forwarded-For": IP SPOOF / FAKE IP
```

untuk fake IP saya hanya membuat alamat ip random, asal-asalan saja.
dengan syntax python seperti ini atau bisa lihat lengkap disource code bawah.

```python
ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
```

{{< raw >}}
source code: <a href="https://pastebin.com/raw/Z8nG0T7s">pastebin</a>
{{< /raw >}}

ketika saya jalankan programnya, ternyata IP limit bypassed. saya mencoba ngeload sekitar
ribuan akun ternyata bisa dan mendapatkan banyak akun yang online (registered) di platform
sfile.mobi.


{{< raw >}}
<img src="/images/pp3.jpg" >
{{< /raw >}}

- status bug: `patched`


# Referensi tentang IP restriction bypass

- 403/401 Bypasses
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/403-and-401-bypasses
- 403/401 bypass hackerone report
https://hackerone.com/reports/991717
- IP restriction (root-me CTF)
https://archiko.my.id/archives/root-me-writeup-ip-restriction-bypass/
- 403 bypass - medium 
https://sapt.medium.com/bypassing-403-protection-to-get-pagespeed-admin-access-822fab64c0b3

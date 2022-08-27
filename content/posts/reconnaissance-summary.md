---
title: summary of reconnaissance for web application bug hunting 🕷 
author: ardho ainullah
date: 2022-08-26
description: panduan dasar untuk melakukan information gathering terhadap web application sebagai awalan untuk melakukan bug hunting
tags: ['hacking']
---

{{< raw >}}
<img src="https://images.unsplash.com/photo-1562813733-b31f71025d54?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=869&q=80">
{{< /raw >}}


**notes**: in this article if you found text like this `here` is a tools or platforms. you just search that on google or other search engines.


# base

- whois: `whois`
- dns enum: `dnsrecon` `nslookup` `dnsx` `dnsenum`

https://www.geeksforgeeks.org/dnsx-dns-toolkit-allow-to-run-multiple-dns-queries/amp/

https://medium.com/geekculture/dns-enumeration-3dc90ca1f670

https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns


- identify web technology: `whatweb` `w3techs` `wappalyzer`
- check webapp firewall: `wafw00f`
- check security headers: `shcheck`
- subdo enum: `subfinder` `sublist3r`
- extracting all IP from collected subdo
- port scanning & banner grabbing: `nmap` `amass` `aquatone`



Using Nmap Scripts: Nmap Banner Grab
https://linuxhint.com/nmap_banner_grab




**mass ports scanning with nmap**
```shell
$ nmap -iL subdolist.txt -Pn -sV -n -T4 -v  -oN output.txt
```


**vuln scan + banner grabbing**
```shell
$ nmap -iL subdolist.txt -Pn -sV -n -T4 -v -d  --script vuln -oN output.txt
```



- check domain takeoverv: `subzy`
- domain & subdo osint: `shodan` `censys`
- check http(s) 80/443 > `httpx` > `altdns` > `nuclei`
- reverse IP lookup `hackertarget` `googledork` `bing`



# Content discovery

- fuzzing
  - get error like sql inject, system crash, dos, etc.

- `ffuf` 
  - search directory, sensitive data, etc.
  - find API path / Endpoint

- `waybackurls`
  - if link possible to vuln. scanning with `nuclei` or fuzzing again with `ffuf`
  for getting vulnerability like sqli.
  - get files from target like php, aspx, etc.

- extract js files 
  - scan endpoint, API, etc.

- github dorking > `githound` 
  - checking leaked credential, tokens, etc.

{{< raw >}}
<img src="https://i.ibb.co/Hx6whny/IMG-20220824-153323.jpg">
{{< /raw >}}

- google dorking
  - content discovery with `google hacking`



# TIPS
• always see web source code because sometimes you can found somethink interesting which not found or not gained in your tool recon.

• if you found admin path like admin/. fuzzing again with ffuf like admin/FUZZ. you can find somethink interesting files or dir again if lucky.





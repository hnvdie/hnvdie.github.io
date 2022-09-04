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


`**notes**: `

- in this article if you found text like this `here` is a tools or platforms. you just search that on google or other search engines.
- this article will be to always updated if me found new techniques or methods.


# base

- whois: `whois`
- ssl information: `sslscan`
- dns enum: `dnsrecon` `nslookup` `dnsx` `dnsenum`
- identify web technology: `whatweb` `w3techs` `wappalyzer` `cmsmap`
- check webapp firewall: `wafw00f`
- check security headers: `shcheck`
- subdo enum: `subfinder` `sublist3r` `knock`
- extracting all IP from collected subdo
- port scanning & banner grabbing: `nmap` `amass` `aquatone` `naabu`
- check domain takeoverv: `subzy`
- domain & subdo osint: `shodan` `censys`
- check http(s) 80/443 > `httpx` > `altdns` > `nuclei`
- reverse IP lookup `hackertarget` `googledork` `bing`



# Content discovery

- fuzzing, `wfuzz`
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

- google hacking
  - content discovery with `google dork`



# Tips
• always see web source code because sometimes you can found somethink interesting which not found or not gained in your tool recon.

• if you found admin path like admin/. fuzzing again with ffuf like admin/FUZZ. you can find somethink interesting files or dir again if lucky.



# Extra resources for you :3

- Cool Recon techniques every hacker misses! 🔥🔥

https://infosecwriteups.com/cool-recon-techniques-every-hacker-misses-1c5e0e294e89

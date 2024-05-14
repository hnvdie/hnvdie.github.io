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


`notes: `

- in this article if you found text like this `here` is a tools or platforms. you just search that on google or other search engines.
- this article will be to always updated if me found new techniques or methods.


# base

- whois: `whois`
- ssl information: `sslscan`
- dns enumeration: `dnsrecon` `nslookup` `dnsx` `dnsenum`
- identify web technology: `whatweb` `wappalyzer` `cmsmap`
- check webapp firewall: `wafw00f`
- check security headers: `shcheck`
- subdo enumeration: `subfinder` `sublist3r` `knock`
- extracting all IP from collected subdodomain
- port scanning & banner grabbing: `nmap` `amass` `aquatone` `naabu`
- check domain takeover: `subzy`
- domain & subdo osint: `shodan` `censys`
- check http(s) 80/443: `httpx` > `altdns` > `nuclei`
- reverse IP lookup `hackertarget` `googledork` `bing`

# Content discovery

**Fuzzing**

> getting directory, files, sensitive data.
> scan error like system crash, sql injection, etc.
> with fuzzing technique

- `wfuzz:` Web application fuzzer
- `ffuf:` Fast web fuzzer written in Go
- `fuzzdb` Dictionary of attack patterns and primitives for black-box application fault injection and resource discovery.

**links and urls**

> getting js files, php, aspx and other interesting files or urls.
> for scanning endpoint, API path, etc.

- `gau:` Fetch known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl.
- `waybackurls:` Fetch all the URLs that the Wayback Machine knows about for a domain
- `getJS:` A tool to fastly get all javascript sources/files
- `linkfinder:` A python script that finds endpoints in JavaScript files
- `assetfinder:` Find domains and subdomains related to a given domain


**Parameters**

- `parameth:` This tool can be used to brute discover GET and POST parameters
- `ParamSpider:` Mining parameters from dark corners of Web Archives
- `ffuf`
- `commix`
**Other helper**

- `gobuster:` Directory/File, DNS and VHost busting tool written in Go
- `gospider:` Gospider - Fast web spider written in Go
- `hakrawler:` Simple, fast web crawler designed for easy, quick discovery of endpoints and assets within a web application
- `git-hound:` Reconnaissance tool for GitHub code search. Finds exposed API keys using pattern matching, commit history searching, and a unique result scoring system.
- `pagodo:` pagodo (Passive Google Dork) - Automate Google Hacking Database scraping and searching


# Extra resources for you :3

- Cool Recon techniques every hacker misses! 🔥🔥

https://infosecwriteups.com/cool-recon-techniques-every-hacker-misses-1c5e0e294e89

# Reconnaissance Report

- **Target:** example.com
- **Scan report generated:** 2026-10-23T12:50:15+01:00

## Scan Summary

- DNS records: 9
- Subdomains: 1
- Services: 7
- URLs/endpoints: 1
- Technologies: 2

## DNS

### A

- `104.20.23.154`
- `172.66.147.243`

### AAAA

- `2606:4700:10::6814:179a`
- `2606:4700:10::ac42:93f3`

### CNAME

- None found

### MX

- `0 .`

### NS

- `hera.ns.cloudflare.com.`
- `elliott.ns.cloudflare.com.`

### TXT

- `"_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9"`
- `"v=spf1 -all"`

## HTTP

### HTTP

- **URL:** http://example.com/
- **Status:** 200
- **Server:** cloudflare
- **Content type:** text/html; charset=utf-8
- **Redirect:** None
- **Security headers:**
  - None recorded

### HTTPS

- **URL:** https://example.com/
- **Status:** 200
- **Server:** cloudflare
- **Content type:** text/html; charset=utf-8
- **Redirect:** None
- **Security headers:**
  - None recorded

## Subdomains

### `www.example.com`
- **A:** 104.20.23.154, 172.66.147.243
- **AAAA:** 2606:4700:10::ac42:93f3, 2606:4700:10::6814:179a

## Services

| Host | Port | Protocol | State | Service | Version |
|---|---:|---|---|---|---|
| example.com | 22 | tcp | unknown | None | Unknown |
| example.com | 80 | tcp | open | http | Unknown |
| example.com | 443 | tcp | open | https | Unknown |
| example.com | 3306 | tcp | unknown | None | Unknown |
| example.com | 5432 | tcp | unknown | None | Unknown |
| example.com | 8000 | tcp | unknown | None | Unknown |
| example.com | 8080 | tcp | open | http | Unknown |

## Technologies

### cloudflare

- **Category:** Web Server
- **Evidence:**
  - Server response header

### Cloudflare

- **Category:** CDN / Reverse proxy
- **Evidence:**
  - Cloudflare-related response header

## URLs and Endpoints

- **Starting URL:** https://example.com/

| URL | Endpoint | Parameters |
|---|---|---|
| https://example.com/ | `/` | `{}` |

## Interesting Assets

- **Open service:** `example.com:80` (http)
- **Open service:** `example.com:443` (https)
- **Open service:** `example.com:8080` (http)

## Errors and Incomplete Scans

No recorded errors. Missing files are reported above.

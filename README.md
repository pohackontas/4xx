
# 🜲 4xx Bypass Toolkit

**Automated path & header fuzzing to detect protected or hidden endpoints behind 401/403 filters**

Lightweight red-team utility for discovering misconfigured access controls through URL payload mutation and header-based bypass techniques.

## Features

-  **Automatic prefix/suffix path fuzzing**
    Generates mutated URL paths based on payloads (e.g. /admin, /../admin/, %2e/admin etc.).
-  **Header-based bypass attempts**
    - X-Original-URL   
    - X-Forwarded-For    
    - X-Custom-IP-Authorization    
- **Cookie support** (--cookies)
-  **Proxy support** (--proxy http://127.0.0.1:8080)
-  **Hide noisy results** (--hide-codes, --hide-length)
-  **Detection of anomalies**
    Highlights suspicious response sizes → possible hidden content.
-  **Lightweight & silent**
    No dependencies except requests.

## Installation

```
git clone https://github.com/yourname/4xx-bypass.git
cd 4xx-bypass
pip3 install -r requirements.txt
```
## Usage

**Basic scan**
```bash
python3 4xx.py -u http://example.com/test/forbidden.html
```
**Use custom cookie**
```bash
python3 4xx.py -u http://example.com/ -c "sessionid=abc123; auth=true"
```
**Use proxy**
```bash
python3 4xx.py -u http://example.com/ --proxy http://127.0.0.1:8080
```
 **Hide noisy response codes**
```bash
python3 4xx.py -u http://example.com/ -hc 404,400,403
```
 **Hide certain response lengths**
 ```bash
 python3 4xx.py -u http://example.com/ -hl 0,31,638
 ```
**Save results to file**
```
python3 4xx.py -u http://example.com/ -o output.txt
```

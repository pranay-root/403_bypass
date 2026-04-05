# GateCrasher v5: Ultimate 403/401 Bypass Tool 🛡️

GateCrasher is a high-performance, multi-threaded penetration testing tool designed to automate the detection of **403 Forbidden** and **401 Unauthorized** bypasses. By combining structural path mutations, header injection, and protocol manipulation, it identifies misconfigurations in WAFs, Proxies, and Backend servers.

## 🚀 Key Features

* **Omni-Vector Mutation Engine:** Automatically generates case-swapping, single/double URL encoding, and null-byte variations.
* **Header Spoofing:** Injects common bypass headers (`X-Forwarded-For`, `X-Original-URL`) and Host-header (`localhost`) spoofing.
* **Multi-Method Fuzzing:** Cycles through all verbs in your `methods.txt` (GET, POST, PUT, PATCH, etc.) against every payload.
* **Advanced Path Normalization:** Tests for double slashes, trailing slashes, and dot-segment bypasses.
* **Smart Filtering:** Uses unique response length filtering to reduce noise and includes a configurable results limit (`-r`).

## 🛠️ Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/pranay-root/403_bypass.git
   cd 403_bypass

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv env
   source env/bin/activate
   ```
   
3. **Install dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```

## 📖 Usage

Basic usage against a protected endpoint:
```bash
python3 gatecrasher.py -u https://target.com/admin -t 10 -r 3
```

### Arguments:
| Flag | Description | Default |
| :--- | :--- | :--- |
| `-u` | Target URL (Required) | None |
| `-t` | Number of concurrent threads | 30 |
| `-fc`| Status codes to filter/ignore | 403,404 |
| `-r` | Max unique results to find before stopping | 3 |

## 🧪 Targeted Bypass Techniques

The tool specifically targets the following common misconfigurations:
1.  **HTTP Verb Tampering:** Testing if restricted paths allow `POST` or `PUT` when `GET` is blocked.
2.  **Case-Sensitivity:** Exploiting systems where `/admin` is blocked but `/Admin` is allowed.
3.  **Path Normalization:** Using `//`, `/./`, or `..;/` to confuse WAF path-matching rules.
4.  **Host Header Spoofing:** Changing the `Host` header to `localhost` to bypass internal-only access controls.
5.  **IP-Based Access Control:** Injecting headers like `X-Forwarded-For: 127.0.0.1` to spoof internal origin.

## ⚠️ Disclaimer
This tool is for educational and authorized security testing purposes only. Usage against targets without prior mutual consent is illegal. The author assumes no liability for misuse.


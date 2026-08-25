# SQLReaper ☠

```
  ███████╗ ██████╗ ██╗     ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗
  ██╔════╝██╔═══██╗██║     ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ███████╗██║   ██║██║     ██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
  ╚════██║██║▄▄ ██║██║     ██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
  ███████║╚██████╔╝███████╗██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
  ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
```

**Automated SQL Injection — Precision. Speed. Depth.**

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![SQLMap](https://img.shields.io/badge/powered%20by-sqlmap-red)

---

> ⚠️ **LEGAL WARNING**
> SQLReaper is intended **exclusively** for authorized penetration testing and security research.
> Use only on systems you **own** or have **explicit written permission** to test.
> Unauthorized use is **illegal** and may result in criminal prosecution.

---

## Features

- **28 automated sqlmap commands** organized across 6 attack phases
- **4 scan profiles**: `quick`, `full`, `stealth`, `waf`
- **Modular architecture** — run only the phases you need
- **Session persistence** — resume interrupted scans with `--resume`
- **Live output** with color-highlighted findings
- **Report generation** — HTML, JSON, and TXT formats
- **Tor support** — route all traffic through SOCKS5
- **WAF bypass** — 6 tamper-script combos built in
- **Desktop notifications** on scan completion (`--notify`)
- **Progress bars** and step headers for clean UX

---

## Installation

```bash
git clone https://github.com/youruser/sqlreaper.git
cd sqlreaper
make install
```

Or manually:

```bash
pip install -r requirements.txt --break-system-packages
sudo apt install sqlmap   # if not already installed
```

---

## Usage

```bash
# Basic scan (all modules, default level/risk)
python3 sqlreaper.py -u "https://target.com/page.php?id=1"

# POST request with cookie
python3 sqlreaper.py -u "https://target.com/login" -d "user=admin&pass=x" -c "SESSID=abc"

# Use a preset profile
python3 sqlreaper.py -u "https://target.com/page.php?id=1" --profile stealth

# Run specific modules only
python3 sqlreaper.py -u "https://target.com/page.php?id=1" --modules recon,dump,bypass

# Generate full reports + route through Tor
python3 sqlreaper.py -u "https://target.com/page.php?id=1" --tor --report

# Resume a previous session
python3 sqlreaper.py --resume ./sqlreaper_results/target_20240101_120000/
```

---

## Profiles

| Profile   | Level | Risk | Threads | Modules                    | Notes                        |
|-----------|-------|------|---------|----------------------------|------------------------------|
| `quick`   | 1     | 1    | 4       | recon, injection           | Fast initial fingerprint     |
| `full`    | 5     | 3    | 8       | all                        | Deep exhaustive scan         |
| `stealth` | 2     | 1    | 1       | recon, injection, bypass   | Low-noise, tamper enabled    |
| `waf`     | 3     | 2    | 2       | injection, bypass          | WAF evasion focused          |

---

## Modules

| Phase       | Tag      | Count | Commands                                                               |
|-------------|----------|-------|------------------------------------------------------------------------|
| Recon       | `RECON`  | 5     | Smart detection, DBMS fingerprint, error parsing, current DB/user, DBA check |
| Injection   | `INJECT` | 6     | All techniques, Boolean, Time-based, Error-based, UNION, Stacked      |
| Dump        | `DUMP`   | 7     | Databases, tables, columns, dump-all, users, passwords, privileges    |
| Bypass      | `BYPASS` | 6     | space2comment, randomcase, multi-tamper, unicode+hex, base64, chunked |
| Crawl       | `CRAWL`  | 2     | Site crawl depth-3, form auto-detection                                |
| OS Access   | `OS`     | 2     | Read /etc/passwd, /etc/shadow                                          |

---

## Output

Each scan creates a timestamped folder under `sqlreaper_results/`:

```
sqlreaper_results/
└── target_com_20240101_120000/
    ├── results.log      # Full sqlmap output
    ├── session.json     # Resume state
    ├── report.html      # Dark-theme HTML report
    ├── report.json      # Machine-readable report
    └── report.txt       # Plain-text summary
```

Use `--output /path/to/dir` to specify a custom output location.

---

## Controls

| Input          | Effect                                 |
|----------------|----------------------------------------|
| `Ctrl+C` once  | Skip current module, continue to next |
| `Ctrl+C` twice | Save session and exit immediately      |

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Install pre-commit hooks: `pip install pre-commit && pre-commit install`
4. Make your changes and run tests: `make test`
5. Submit a pull request

Code style is enforced with `black`, `isort`, and `flake8` (line length 100).

---

## License

MIT License — see [LICENSE](LICENSE) for details.

SQLReaper is a wrapper around [sqlmap](https://sqlmap.org/), which is licensed separately under GPLv2.

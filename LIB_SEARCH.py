import os
import re
import sys
import subprocess
import importlib
from pathlib import Path
from datetime import datetime, timezone


def ensure_module(mod_name: str, pip_spec: str, fatal: bool = True):
    try:
        return importlib.import_module(mod_name)
    except ImportError:
        print(f"{mod_name} not found, installing via pip ...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pip_spec])
        except Exception as e:
            if fatal:
                raise SystemExit(f"Failed to install {pip_spec}: {e}")
            print(f"[WARN] Failed to install {pip_spec}, proceeding without color: {e}")
            return None
        return importlib.import_module(mod_name)


# Dependencies (auto-install)
requests = ensure_module("requests", "requests>=2.31.0", fatal=True)  # type: ignore
colorama_mod = ensure_module("colorama", "colorama>=0.4.6", fatal=False)
if colorama_mod:
    from colorama import Fore, Style, init as colorama_init

    colorama_init()

    def c(text, color):
        return f"{color}{text}{Style.RESET_ALL}"
else:
    class _Dummy:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
        RESET = RESET_ALL = ""

    Fore = Style = _Dummy()

    def c(text, color):
        return text

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HIGH_RISK_CVSS_THRESHOLD = 7.0


def parse_name_version(line: str):
    """
    Accepts:
      Firebase-10.24.0
      AFNetworking-4.0.1
      DPHSDK-v3.4.3
    Returns: (name, version) or (name, "") if cannot parse version.
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return None

    # Split by last '-' or '_' to better tolerate names with '-'
    m = re.match(r"^(?P<name>.+?)[-_](?P<ver>v?\d+(?:\.\d+)*.*)$", s)
    if not m:
        return (s, "")

    name = m.group("name").strip()
    ver = m.group("ver").strip()
    if ver.lower().startswith("v"):
        ver = ver[1:]
    return (name, ver)


def read_items_from_txt(path: str):
    p = Path(path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"File not found: {path}")
    lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    items = []
    for ln in lines:
        parsed = parse_name_version(ln)
        if parsed:
            items.append((ln.strip(), parsed[0], parsed[1]))
    return items


def read_items_from_paste():
    print("Paste items (blank line to finish):")
    items = []
    while True:
        ln = input()
        if not ln.strip():
            break
        parsed = parse_name_version(ln)
        if parsed:
            items.append((ln.strip(), parsed[0], parsed[1]))
    return items


def best_cvss_score_nvd(vuln: dict):
    metrics = (vuln.get("cve") or {}).get("metrics") or {}
    best = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key) or []:
            data = m.get("cvssData") or {}
            score = data.get("baseScore") or m.get("baseScore")
            if score is None:
                continue
            try:
                score = float(score)
            except Exception:
                continue
            if best is None or score > best:
                best = score
    return best


def get_description_nvd(vuln: dict):
    desc_list = (vuln.get("cve") or {}).get("descriptions") or []
    for d in desc_list:
        if str(d.get("lang", "")).lower() == "en":
            return (d.get("value") or "").strip()
    if desc_list:
        return (desc_list[0].get("value") or "").strip()
    return ""


def extract_high_risk_vulns_nvd(vuln: dict):
    best = best_cvss_score_nvd(vuln)
    is_high = (best is not None and best >= HIGH_RISK_CVSS_THRESHOLD)
    return is_high, best


def nvd_query(name: str, version: str, api_key: str | None = None):
    params = {
        "keywordSearch": f"{name} {version}",
        "resultsPerPage": 100,
    }
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    r = requests.get(NVD_CVE_API, params=params, headers=headers, timeout=30)
    try:
        r.raise_for_status()
    except requests.HTTPError as e:
        detail = r.text.strip() if r is not None else ""
        raise requests.HTTPError(f"{e} | {detail}", response=r)
    data = r.json()
    return data.get("vulnerabilities") or []


def main():
    scan_start = datetime.now(timezone.utc)
    print(c("=== CYBER VULN SCAN ===", Fore.CYAN))
    print(c(f" API      : NIST NVD CVE API (2.0)", Fore.MAGENTA))
    print(c(f" Endpoint : {NVD_CVE_API}", Fore.MAGENTA))
    print(c(f" Started  : {scan_start.isoformat().replace('+00:00', 'Z')}", Fore.MAGENTA))

    api_key = os.environ.get("NVD_API_KEY")

    print("Select input mode:")
    print("1) Paste items (line-by-line, blank line to finish)")
    print("2) Load from TXT file (newline separated)")
    mode = input("Enter 1 or 2: ").strip()

    if mode == "1":
        raw_items = read_items_from_paste()
    elif mode == "2":
        # Use libs.txt in the same directory as this script for input/output
        libs_path = Path(__file__).parent / "libs.txt"
        if not libs_path.exists():
            libs_path.write_text(
                "# Add newline-separated library lines (e.g. Firebase-10.24.0)\n",
                encoding="utf-8",
            )
            print(c(f"Created {libs_path}", Fore.YELLOW))
            input("Edit the file as needed, then press Enter to continue...")
        else:
            print(c(f"Using {libs_path}", Fore.MAGENTA))

        raw_items = read_items_from_txt(str(libs_path))

        # Offer to save a normalized, de-duplicated list back to libs.txt
        raw_lines = []
        _seen_raw = set()
        for raw, _name, _ver in raw_items:
            if raw not in _seen_raw:
                _seen_raw.add(raw)
                raw_lines.append(raw)

        try:
            resp = input("Save normalized list back to libs.txt? (Y/n): ").strip().lower()
        except Exception:
            resp = "y"
        if resp in ("", "y", "yes"):
            libs_path.write_text("\n".join(raw_lines) + ("\n" if raw_lines else ""), encoding="utf-8")
            print(c("libs.txt updated.", Fore.GREEN))
    else:
        print("Invalid mode.")
        return

    items = []
    seen = set()
    for raw, name, ver in raw_items:
        key = (name, ver)
        if key in seen:
            continue
        seen.add(key)
        items.append((raw, name, ver))

    if not items:
        print("NO RESULTS")
        return

    per_input = []
    seen = set()
    for raw, name, ver in items:
        entry = {"raw": raw, "name": name, "ver": ver, "vulns": [], "error": None}

        try:
            vulns = nvd_query(name, ver, api_key=api_key)
        except requests.HTTPError as e:
            entry["error"] = f"NVD query failed: {e}"
            per_input.append(entry)
            continue
        except Exception as e:
            entry["error"] = f"NVD query error: {e}"
            per_input.append(entry)
            continue

        for v in vulns:
            is_high, cvss = extract_high_risk_vulns_nvd(v)
            if not is_high:
                continue
            cve_data = v.get("cve") or {}
            cve_id = cve_data.get("id", "")
            key = (raw, cve_id)
            if key in seen:
                continue
            seen.add(key)
            entry["vulns"].append({
                "cve_id": cve_id,
                "cvss": cvss,
                "summary": get_description_nvd(v)
            })

        entry["vulns"].sort(key=lambda x: (x["cvss"] if x["cvss"] is not None else -1), reverse=True)
        per_input.append(entry)

    if not per_input:
        print("NO INPUTS")
        return

    for entry in per_input:
        print(c(f"\n>>>[ {entry['raw']} ]<<<", Fore.CYAN))
        if entry["error"]:
            print(c(f" !! {entry['error']}", Fore.YELLOW))
        if not entry["vulns"]:
            print(c(" :: NO RESULT", Fore.RED))
            continue
        for v in entry["vulns"]:
            print(c(f" :: CVE {v['cve_id']} | CVSS {v['cvss']:.1f}", Fore.GREEN))
            if v["summary"]:
                print(c(f"    {v['summary']}", Fore.WHITE))
            if v["cve_id"]:
                print(c(f"    https://nvd.nist.gov/vuln/detail/{v['cve_id']}", Fore.BLUE))

    scan_end = datetime.now(timezone.utc)
    duration = (scan_end - scan_start).total_seconds()
    print(c("\n=== SCAN COMPLETE ===", Fore.CYAN))
    print(c(f" Finished : {scan_end.isoformat().replace('+00:00', 'Z')}", Fore.MAGENTA))
    print(c(f" Duration : {duration:.2f} seconds", Fore.MAGENTA))
    print(c(" Source   : Results based on NIST NVD CVE API", Fore.MAGENTA))


if __name__ == "__main__":
    main()

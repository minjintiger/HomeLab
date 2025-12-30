import argparse
import csv
import datetime as dt
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import paramiko
import requests
import yaml
from jinja2 import Environment, FileSystemLoader


# -----------------------------
# helpers
# -----------------------------
def utc_now() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def now_case_id_local() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")

def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def truncate(s: str, limit: int = 6000) -> str:
    s = (s or "").strip()
    return s if len(s) <= limit else s[:limit] + "\n...[truncated]"

def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def write_text(path: Path, text: str) -> None:
    path.write_text(text or "", encoding="utf-8")

def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")

def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = sorted({k for r in rows for k in r.keys()})
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

def render_template(template_dir: Path, template_name: str, out_path: Path, ctx: Dict[str, Any]) -> None:
    env = Environment(loader=FileSystemLoader(str(template_dir)))
    tpl = env.get_template(template_name)
    out_path.write_text(tpl.render(**ctx), encoding="utf-8")


# -----------------------------
# SSH
# -----------------------------
@dataclass
class SSHResult:
    stdout: str
    stderr: str
    exit_code: int

class SSHRunner:
    def __init__(self, host: str, user: str, key_path: str, timeout_sec: int = 12):
        self.host = host
        self.user = user
        self.key_path = key_path
        self.timeout_sec = timeout_sec

    def run(self, cmd: str) -> SSHResult:
        # Paramiko supports Ed25519 keys via Ed25519Key
        key = paramiko.Ed25519Key.from_private_key_file(self.key_path)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.host,
            username=self.user,
            pkey=key,
            timeout=self.timeout_sec,
            banner_timeout=self.timeout_sec,
            auth_timeout=self.timeout_sec,
        )
        try:
            stdin, stdout, stderr = client.exec_command(cmd)
            out = stdout.read().decode(errors="ignore")
            err = stderr.read().decode(errors="ignore")
            exit_code = stdout.channel.recv_exit_status()
            return SSHResult(out, err, exit_code)
        finally:
            client.close()


# -----------------------------
# Splunk REST API (dispatch saved report)
# -----------------------------
class SplunkAPI:
    """
    Dispatch a saved report/search, wait for completion, export results as JSON (then we save CSV).
    Uses token auth: Authorization: Bearer <token>
    """
    def __init__(self, base_url: str, token: str, verify_tls: bool, owner: str = "nobody", app: str = "search"):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.verify_tls = verify_tls
        self.owner = owner
        self.app = app

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def dispatch_saved(self, saved_name: str, time_range: str) -> str:
        # Provide earliest_time/latest_time to control time range
        url = f"{self.base_url}/servicesNS/nobody/search/saved/searches/{quote(saved_name)}/dispatch"
        resp = requests.post(
            url,
            headers=self._headers(),
            data={"output_mode": "json", "dispatch.earliest_time": time_range, "dispatch.latest_time": "now"},
            verify=self.verify_tls,
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        sid = data.get("sid")
        if not sid:
            raise RuntimeError(f"Splunk dispatch did not return sid. Response: {data}")
        return sid

    def wait_done(self, sid: str, timeout_sec: int = 90) -> None:
        url = f"{self.base_url}/services/search/jobs/{sid}"
        start = time.time()
        while True:
            resp = requests.get(
                url,
                headers=self._headers(),
                params={"output_mode": "json"},
                verify=self.verify_tls,
                timeout=20,
            )
            resp.raise_for_status()
            content = resp.json()["entry"][0]["content"]
            if bool(content.get("isDone", False)):
                return
            if time.time() - start > timeout_sec:
                raise TimeoutError(f"Splunk job timeout ({timeout_sec}s): {sid}")
            time.sleep(2)

    def results_json(self, sid: str, count: int = 500) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/services/search/jobs/{sid}/results"
        resp = requests.get(
            url,
            headers=self._headers(),
            params={"output_mode": "json", "count": count},
            verify=self.verify_tls,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get("results", [])


# -----------------------------
# main orchestration
# -----------------------------
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--nmap", default=None, help="Override nmap command (otherwise config scenario_defaults.nmap_command)")
    ap.add_argument("--time-range", default=None, help="Override Splunk earliest_time, e.g. -30m")
    args = ap.parse_args()

    cfg = load_yaml(Path(args.config))

    evidence_base = Path(cfg["controller"]["evidence_dir"])
    case_id = now_case_id_local()
    evidence_dir = evidence_base / case_id
    safe_mkdir(evidence_dir)

    steps: List[Dict[str, Any]] = []
    run_log: Dict[str, Any] = {
        "case_id": case_id,
        "generated_utc": utc_now(),
        "evidence_dir": str(evidence_dir),
        "steps": steps,
    }

    # Save config snapshot (safe: no token inside)
    write_json(evidence_dir / "config_used.json", cfg)

    key_path = cfg["ssh"]["key_path"]
    timeout_sec = int(cfg["ssh"].get("timeout_sec", 12))

    hosts = cfg["hosts"]
    paths = cfg["paths"]

    # nmap command
    nmap_cmd = args.nmap or cfg["scenario_defaults"]["nmap_command"]
    if "<TARGET_IP>" in nmap_cmd:
        raise ValueError("Replace <TARGET_IP> in nmap command (config.yaml or --nmap).")

    # Splunk token from env
    token_env = cfg["splunk_api"]["token_env"]
    token = os.environ.get(token_env, "").strip()
    if not token:
        raise RuntimeError(f"Missing Splunk token in environment variable: {token_env}")

    time_range = args.time_range or cfg["scenario_defaults"].get("time_range", "-30m")

    kali = SSHRunner(host=hosts["kali"]["ip"], user=hosts["kali"]["user"], key_path=key_path, timeout_sec=timeout_sec)
    ubuntu = SSHRunner(host=hosts["ubuntu"]["ip"], user=hosts["ubuntu"]["user"], key_path=key_path, timeout_sec=timeout_sec)

    # Step 1: Kali attack (Nmap)
    steps.append({"name": "Kali - Nmap attack", "status": "STARTED"})
    write_text(evidence_dir / "attack_command.txt", nmap_cmd + "\n")
    res = kali.run(nmap_cmd)
    write_text(evidence_dir / "kali_attack_stdout.txt", res.stdout)
    write_text(evidence_dir / "kali_attack_stderr.txt", res.stderr)
    steps[-1]["status"] = "OK" if res.exit_code == 0 else f"EXIT_{res.exit_code}"

    # Step 2: Ubuntu snapshots (Suricata + logs)
    steps.append({"name": "Ubuntu - Suricata status", "status": "STARTED"})
    res2 = ubuntu.run("sudo systemctl status suricata --no-pager")
    write_text(evidence_dir / "ubuntu_suricata_status.txt", res2.stdout + "\n" + res2.stderr)
    steps[-1]["status"] = "OK" if res2.exit_code == 0 else f"EXIT_{res2.exit_code}"

    steps.append({"name": "Ubuntu - eve.json tail", "status": "STARTED"})
    eve = paths["suricata_eve_json"]
    res3 = ubuntu.run(f"sudo tail -n 200 {eve}")
    write_text(evidence_dir / "ubuntu_eve_tail.json", res3.stdout)
    steps[-1]["status"] = "OK" if res3.exit_code == 0 else f"EXIT_{res3.exit_code}"

    steps.append({"name": "Ubuntu - auth.log tail", "status": "STARTED"})
    auth = paths["auth_log"]
    res4 = ubuntu.run(f"sudo tail -n 200 {auth}")
    write_text(evidence_dir / "ubuntu_auth_tail.txt", res4.stdout)
    steps[-1]["status"] = "OK" if res4.exit_code == 0 else f"EXIT_{res4.exit_code}"

    # Step 3: Splunk saved report -> CSV
    steps.append({"name": "Splunk - dispatch saved report and export CSV", "status": "STARTED"})
    spl = SplunkAPI(
        base_url=cfg["splunk_api"]["base_url"],
        token=token,
        verify_tls=bool(cfg["splunk_api"].get("verify_tls", True)),
        owner=cfg["splunk_api"].get("owner", "nobody"),
        app=cfg["splunk_api"].get("app", "search"),
    )


    report_name = cfg["splunk_api"]["saved_report_name"]
    sid = spl.dispatch_saved(report_name, time_range=time_range)
    spl.wait_done(sid, timeout_sec=120)
    rows = spl.results_json(sid, count=500)

    csv_name = "splunk_LAB6_Suricata_SSH_Alerts.csv"
    csv_path = evidence_dir / csv_name
    write_csv(csv_path, rows)

    steps[-1]["status"] = "OK"
    steps[-1]["note"] = f"sid={sid}, rows={len(rows)}"

    # Write run log
    write_json(evidence_dir / "run_log.json", run_log)

    # Generate incident report (Lab7-facing)
    ctx = {
        "case_id": case_id,
        "generated_utc": run_log["generated_utc"],
        "hosts": hosts,
        "paths": paths,
        "nmap_command": nmap_cmd,
        "evidence_dir": str(evidence_dir).replace("\\", "/"),
        "steps": steps,
        "splunk": {
            "report_name": report_name,
            "time_range": time_range,
            "rows": len(rows),
            "csv_name": csv_name,
        },
    }
    render_template(Path("templates"), "incident_report.md.j2", evidence_dir / "incident_response_Report.md", ctx)

    print(f"[OK] Evidence saved: {evidence_dir}")
    print(f"[OK] Report: {evidence_dir / 'incident_response_Report.md'}")

if __name__ == "__main__":
    main()

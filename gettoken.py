#!/usr/bin/env python3
"""
sti_pa_spc_token.py
Production STI-PA flow:
  1) Login (API user) -> access + refresh token
  2) Request SPC token (OCN) -> SPC JWT for CA issuance

Env vars (create .env next to this script):
  API_USER=alamo-api
  API_PASS=your-strong-password
  ACC_ID=102604
  OCN=587L
  EXPIRY_DAYS=14
  BASE_URL=https://authenticate-api.iconectiv.com
  OUT_DIR=/etc/asterisk/certs/stirshaken
"""

import json
import os
import sys
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

# ---- config ----
TIMEOUT = 20
HDR_JSON = {"Content-Type": "application/json"}
LOGIN_PATH = "/api/v1/auth/login"
REFRESH_PATH = "/api/v1/auth/refreshToken"
SPC_GENERIC_PATH = "/api/v1/spcToken"
SPC_ACCT_PATH_TMPL = "/api/v1/account/{acc_id}/token/"


def die(msg, code=1, payload=None):
    sys.stderr.write(f"[error] {msg}\n")
    if payload:
        sys.stderr.write(json.dumps(payload, indent=2) + "\n")
    sys.exit(code)


def require(var):
    v = os.getenv(var)
    if not v:
        die(f"Missing required env var: {var}")
    return v


def login(base_url, user, pw):
    url = base_url + LOGIN_PATH
    body = {"userId": user, "password": pw}
    r = requests.post(url, headers=HDR_JSON, json=body, timeout=TIMEOUT)
    if r.status_code != 200:
        die(f"Login failed HTTP {r.status_code}", r.json() if r.headers.get("content-type","").startswith("application/json") else {"text":r.text})
    data = r.json()
    at = data.get("accessToken")
    rt = data.get("refreshToken")
    if not at or not rt:
        die("Login response missing access/refresh token", data)
    return data  # includes expiries in many tenants


def refresh(base_url, refresh_token):
    url = base_url + REFRESH_PATH
    body = {"refreshToken": refresh_token}
    r = requests.post(url, headers=HDR_JSON, json=body, timeout=TIMEOUT)
    if r.status_code != 200:
        die(f"Refresh failed HTTP {r.status_code}", r.json() if r.headers.get("content-type","").startswith("application/json") else {"text":r.text})
    data = r.json()
    at = data.get("accessToken")
    if not at:
        die("Refresh response missing accessToken", data)
    return data


def request_spc(base_url, access_token, ocn, expiry_days, acc_id=None):
    # Use standard Bearer token authentication as per API docs
    hdr = {"Authorization": access_token, **HDR_JSON}
    
    # API expects atc object structure according to documentation
    payload = {
        "atc": {
            "tktype": "SPC",
            "tkvalue": ocn,
            "ca": True,
            "fingerprint": ""  # May need to be populated based on requirements
        }
    }

    # Try account-scoped endpoint first (as per API docs: /api/v1/account/:id/token/)
    if acc_id:
        url = base_url + SPC_ACCT_PATH_TMPL.format(acc_id=acc_id)
        print(f"[debug] requesting SPC token from account-scoped endpoint: {url}")
        r = requests.post(url, headers=hdr, json=payload, timeout=TIMEOUT)
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            print(f"[debug] account-scoped endpoint returned 404, trying generic endpoint")
        else:
            print(f"[debug] account-scoped endpoint failed with {r.status_code}: {r.text}")
        
    # Fallback to generic endpoint if account-scoped fails
    url = base_url + SPC_GENERIC_PATH
    print(f"[debug] requesting SPC token from generic endpoint: {url}")
    r = requests.post(url, headers=hdr, json=payload, timeout=TIMEOUT)
    if r.status_code != 200:
        die(f"SPC request failed HTTP {r.status_code}", r.json() if r.headers.get("content-type","").startswith("application/json") else {"text":r.text})
    return r.json()


def save_outputs(out_dir, access_json, refresh_json, spc_json):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    (out / "access.json").write_text(json.dumps(access_json, indent=2))
    if refresh_json:
        (out / "refresh.json").write_text(json.dumps(refresh_json, indent=2))
    (out / "spc.json").write_text(json.dumps(spc_json, indent=2))

    # Save bare SPC token for convenience
    token = spc_json.get("spcToken") or spc_json.get("token")
    if token:
        (out / "spc-token.txt").write_text(token)
        print(f"[ok] wrote {out/'spc-token.txt'}")
    else:
        print("[warn] SPC token field not found; see spc.json")


def main():
    load_dotenv()

    base_url = os.getenv("BASE_URL", "https://authenticate-api.iconectiv.com").rstrip("/")
    user = require("API_USER")
    pw = require("API_PASS")
    acc_id = os.getenv("ACC_ID")  # account-scoped path; recommended in prod
    ocn = require("OCN")
    expiry_days = int(os.getenv("EXPIRY_DAYS", "14"))
    out_dir = os.getenv("OUT_DIR", "./sti-pa-output")

    print(f"[info] login as API user '{user}' to {base_url}")
    access_obj = login(base_url, user, pw)
    access_token = access_obj.get("accessToken")
    refresh_token = access_obj.get("refreshToken")

    # Optional: demonstrate refresh flow when needed
    refresh_obj = None
    # if you want to proactively refresh, uncomment:
    # time.sleep(2)
    # refresh_obj = refresh(base_url, refresh_token)
    # access_token = refresh_obj.get("accessToken")

    print(f"[info] requesting SPC token for OCN {ocn} ({expiry_days} days)")
    spc_obj = request_spc(base_url, access_token, ocn, expiry_days, acc_id=acc_id)

    save_outputs(out_dir, access_obj, refresh_obj, spc_obj)
    print("[ok] done.")


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as e:
        die(f"HTTP error: {e}")

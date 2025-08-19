#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# ACME/STI-PA SPC-token helper for SHAKEN (RFC 9448 / ATIS-1000080)

import base64, binascii, hashlib, json, os, sys
import requests
from dotenv import load_dotenv
from pathlib import Path

# cryptography for EC key + SPKI DER
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# pyasn1 for TNAuthList ASN.1
from pyasn1.type import univ, char, tag
from pyasn1.codec.der.encoder import encode as der_encode

# -------------------------
# helpers (per RFC 9448 / ATIS-1000080)
# -------------------------

def build_tnauthlist_spc_der(spc: str) -> bytes:
    """
    TNAuthList ::= SEQUENCE { spc [0] IA5String }   # SPC-only case
    tkvalue = base64( DER(TNAuthList) )
    OpenSSL conf equivalent:
      asn1=SEQUENCE:tn_auth_list
      [tn_auth_list]
      field1=EXP:0,IA5:<SPC>
    """
    spc_upper = spc.strip().upper()
    spc_tagged = char.IA5String(spc_upper).subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )
    tnauthlist = univ.Sequence()
    tnauthlist.setComponentByPosition(0, spc_tagged)
    return der_encode(tnauthlist)

def sha256_fingerprint_of_spki(public_key) -> str:
    """
    Compute SHA256 fingerprint of ACME account *public key* (SPKI DER),
    formatted as 'SHA256 XX:YY:...' (RFC 9448 'fingerprint') """
    spki_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    h = hashlib.sha256(spki_der).hexdigest().upper()
    pairs = ":".join(h[i:i+2] for i in range(0, len(h), 2))
    return f"SHA256 {pairs}"

def b64_no_newlines(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

# -------------------------
# config
# -------------------------

load_dotenv()
BASE_URL   = os.getenv("BASE_URL", "https://authenticate-api.iconectiv.com").rstrip("/")
API_USER   = os.getenv("API_USER")   # API userId (aligned with .env)
API_PASS   = os.getenv("API_PASS")   # API password (aligned with .env)
SPC        = os.getenv("OCN")        # SPC from OCN env var (aligned with .env)
ACC_ID     = SPC                     # Use OCN as account ID
OUT_DIR    = os.getenv("OUT_DIR", "./outputs")  # Output directory
TOKEN_PATH = os.getenv("TOKEN_PATH", f"/api/v1/account/{ACC_ID}/token")  # per STI-PA spec

for name, val in [("API_USER", API_USER), ("API_PASS", API_PASS), ("OCN", SPC)]:
    if not val:
        sys.exit(f"Missing env: {name}")

s = requests.Session()

# -------------------------
# 1) login -> accessToken (valid ~1h)  (RFC 9448 flow) 
# -------------------------
login_url = f"{BASE_URL}/api/v1/auth/login"
r = s.post(login_url, json={"userId": API_USER, "password": API_PASS}, timeout=20)
r.raise_for_status()
data = r.json()
if data.get("status") != "success":
    sys.exit(f"Login failed: {data}")
access_token = data["accessToken"]

# -------------------------
# 2) ACME account key + fingerprint (RFC 9448 §3; RFC 9447 tkauth-type)
#    Load existing key if available, otherwise generate new ES256 key.
# -------------------------
out_path = Path(OUT_DIR)
out_path.mkdir(parents=True, exist_ok=True)

acme_private_path = out_path / "acme_account_private.pem"
acme_public_path = out_path / "acme_account_public.pem"

if acme_private_path.exists():
    # Load existing ACME account key
    print(f"[info] Loading existing ACME account key from {acme_private_path}")
    acct_key_pem = acme_private_path.read_bytes()
    acct_key = serialization.load_pem_private_key(acct_key_pem, password=None)
    acct_pub = acct_key.public_key()
    print(f"[info] Using existing ACME account key")
else:
    # Generate new ACME account key
    print(f"[info] Generating new ACME account key (ES256/P-256)")
    acct_key = ec.generate_private_key(ec.SECP256R1())  # ES256
    acct_pub = acct_key.public_key()
    
    # Save the new key immediately
    acct_key_pem = acct_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    acme_private_path.write_bytes(acct_key_pem)
    
    acct_pub_pem = acct_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    acme_public_path.write_bytes(acct_pub_pem)
    print(f"[info] New ACME account key saved to {acme_private_path}")

fingerprint = sha256_fingerprint_of_spki(acct_pub)

# -------------------------
# 3) TNAuthList DER -> tkvalue  (base64 of ASN.1 DER) per RFC 9448 / RFC 8226
# -------------------------
tnauthlist_der = build_tnauthlist_spc_der(SPC)
tkvalue = b64_no_newlines(tnauthlist_der)

# -------------------------
# 4) Build atc and request SPC token
# -------------------------
atc = {
    "tktype": "TNAuthList",   # RFC 9448 requirement
    "tkvalue": tkvalue,       # base64(DER(TNAuthList)) (RFC 9448 / RFC 8226)
    "ca": False,              # end-entity
    "fingerprint": fingerprint
}

hdrs = {
    "Authorization": f"{access_token}",
    "Content-Type": "application/json",
    "Accept": "application/jose+json"
}
token_url = f"{BASE_URL}{TOKEN_PATH}"
r = s.post(token_url, headers=hdrs, json={"atc": atc}, timeout=30)
r.raise_for_status()
resp = r.json()
if resp.get("status") != "success":
    sys.exit(f"SPC token error: {resp}")

# -------------------------
# 5) Save outputs persistently
# -------------------------
# Note: ACME keys are already saved in step 2 above

# Save login response
login_data = {
    "status": data.get("status"),
    "accessToken": data.get("accessToken"),
    "refreshToken": data.get("refreshToken"),
    "message": data.get("message")
}
(out_path / "login.json").write_text(json.dumps(login_data, indent=2))

# Save fingerprint (always update in case key was reused)
(out_path / "acme-fingerprint.txt").write_text(fingerprint)

# Save TNAuthList DER and base64
(out_path / "tnauthlist.der").write_bytes(tnauthlist_der)
(out_path / "tnauthlist-b64.txt").write_text(tkvalue)

# Save ATC structure
atc_data = {
    "atc": atc,
    "spc": SPC,
    "account_id": ACC_ID,
    "fingerprint": fingerprint
}
(out_path / "atc.json").write_text(json.dumps(atc_data, indent=2))

# Save SPC token response
spc_response = {
    "status": resp.get("status"),
    "message": resp.get("message"),
    "spcToken": resp.get("token"),
    "crl": resp.get("crl")
}
(out_path / "spc-response.json").write_text(json.dumps(spc_response, indent=2))

# Save bare SPC token for convenience
spc_token = resp.get("token")
if spc_token:
    (out_path / "spc-token.txt").write_text(spc_token)
    print(f"[ok] SPC token saved to {out_path / 'spc-token.txt'}")
else:
    print("[warn] No SPC token in response")

# Print summary
print(f"[ok] All outputs saved to {out_path}/")
print(f"[ok] ACME account private key: {out_path / 'acme_account_private.pem'}")
print(f"[ok] ACME account public key: {out_path / 'acme_account_public.pem'}")
print(f"[ok] Fingerprint: {fingerprint}")
print(f"[ok] SPC: {SPC}")

# Also print JSON response for compatibility
print(json.dumps(spc_response, indent=2))

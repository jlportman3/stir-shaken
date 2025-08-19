#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# ACME/STI-PA SPC-token helper for SHAKEN (RFC 9448 / ATIS-1000080)

import base64, binascii, hashlib, json, os, sys
import requests
from dotenv import load_dotenv

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
ICON_USER  = os.getenv("ICON_USER")  # API userId
ICON_PASS  = os.getenv("ICON_PASS")  # API password
ACC_ID     = os.getenv("ACC_ID")     # STI-PA account id (numeric)
SPC        = os.getenv("SPC")        # e.g. 587L or 8864 (your SPC from STI-PA)
TOKEN_PATH = os.getenv("TOKEN_PATH", f"/api/v1/account/{ACC_ID}/token")  # per STI-PA spec

for name, val in [("ICON_USER", ICON_USER), ("ICON_PASS", ICON_PASS), ("ACC_ID", ACC_ID), ("SPC", SPC)]:
    if not val:
        sys.exit(f"Missing env: {name}")

s = requests.Session()

# -------------------------
# 1) login -> accessToken (valid ~1h)  (RFC 9448 flow) 
# -------------------------
login_url = f"{BASE_URL}/api/v1/auth/login"
r = s.post(login_url, json={"userId": ICON_USER, "password": ICON_PASS}, timeout=20)
r.raise_for_status()
data = r.json()
if data.get("status") != "success":
    sys.exit(f"Login failed: {data}")
access_token = data["accessToken"]

# -------------------------
# 2) ACME account key + fingerprint (RFC 9448 §3; RFC 9447 tkauth-type)
#    You can persist these; demo generates ephemeral ES256 key.
# -------------------------
acct_key = ec.generate_private_key(ec.SECP256R1())  # ES256
acct_pub = acct_key.public_key()
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
print(json.dumps({
    "message": resp.get("message"),
    "spcToken": resp.get("token"),
    "crl": resp.get("crl")
}, indent=2))

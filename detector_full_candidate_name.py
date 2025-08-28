#!/usr/bin/env python3

# Script to detect & redact PII from a CSV file
# Usage: python3 detector_full_candidate_name.py input.csv
# Output: redacted_output_candidate_full_name.csv

import sys
import csv
import json
import re

# regexes for detection
re_phone   = re.compile(r"\d{10}")
re_aadhar  = re.compile(r"\d{12}")
re_passport = re.compile(r"[A-Z][0-9]{7}")
re_email   = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
re_upi     = re.compile(r"[A-Za-z0-9.\-_]+@[A-Za-z]{2,}")
re_ipv4    = re.compile(r"((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)")

def mask_phone(v):
    return v[:2] + "XXXXXX" + v[-2:] if len(v) == 10 else v

def mask_aadhar(v):
    return "XXXX XXXX " + v[-4:] if len(v) == 12 else v

def mask_passport(v):
    return v[0] + "XXXXX" + v[-2:] if re_passport.fullmatch(v) else v

def mask_upi(v):
    if "@" not in v: return v
    user, dom = v.split("@", 1)
    return (user[:2] + "XXX@" + dom) if len(user) > 2 else "XX@" + dom

def mask_name(fullname):
    parts = fullname.split()
    return " ".join([p[0] + "X"*(len(p)-1) for p in parts])

def mask_email(v):
    user, dom = v.split("@", 1)
    return (user[:2] + "XXX@" + dom) if len(user) > 2 else "XX@" + dom

def looks_like_full_name(val, fn, ln):
    if val and len(val.strip().split()) >= 2:
        return True
    if fn and ln:
        return True
    return False

def has_physical_address(addr, city, pin):
    return bool(addr and city and pin)

def detect_standalone(d):
    phone = str(d.get("phone", "")).strip()
    contact = str(d.get("contact", "")).strip()
    aadhar = str(d.get("aadhar", "")).strip()
    passport = str(d.get("passport", "")).strip()
    upi = str(d.get("upi_id", "")).strip()

    if re_phone.fullmatch(phone) or re_phone.fullmatch(contact):
        return True
    if re_aadhar.fullmatch(aadhar):
        return True
    if re_passport.fullmatch(passport):
        return True
    if re_upi.fullmatch(upi):
        return True
    return False

def redact_standalone(d):
    for k in ["phone","contact"]:
        if k in d and re_phone.fullmatch(str(d[k]).strip()):
            d[k] = mask_phone(str(d[k]).strip())
    if "aadhar" in d and re_aadhar.fullmatch(str(d["aadhar"]).strip()):
        d["aadhar"] = mask_aadhar(str(d["aadhar"]).strip())
    if "passport" in d and re_passport.fullmatch(str(d["passport"]).strip()):
        d["passport"] = mask_passport(str(d["passport"]).strip())
    if "upi_id" in d and re_upi.fullmatch(str(d["upi_id"]).strip()):
        d["upi_id"] = mask_upi(str(d["upi_id"]).strip())

def detect_combinatorial(d):
    name_ok = looks_like_full_name(d.get("name",""), d.get("first_name",""), d.get("last_name",""))
    email_ok = re_email.fullmatch(str(d.get("email","")).strip()) is not None
    addr_ok = has_physical_address(d.get("address",""), d.get("city",""), d.get("pin_code",""))
    dev_ok = bool(d.get("device_id")) or (re_ipv4.fullmatch(str(d.get("ip_address","")).strip()) is not None)
    return {"name":name_ok, "email":email_ok, "address":addr_ok, "device":dev_ok}

def redact_combinatorial(d, comp):
    active = [k for k,v in comp.items() if v]
    if len(active) < 2:  # needs >=2
        return
    if comp["name"]:
        if d.get("name"): d["name"] = mask_name(d["name"])
        if d.get("first_name"): d["first_name"] = mask_name(d["first_name"])
        if d.get("last_name"): d["last_name"] = mask_name(d["last_name"])
    if comp["email"] and d.get("email"):
        d["email"] = mask_email(d["email"])
    if comp["address"]:
        for k in ["address","city","pin_code"]:
            if d.get(k): d[k] = "[REDACTED_PII]"
    if comp["device"]:
        for k in ["device_id","ip_address"]:
            if d.get(k): d[k] = "[REDACTED_PII]"

def process_record(d):
    pii = False
    if detect_standalone(d):
        pii = True
        redact_standalone(d)
    comp = detect_combinatorial(d)
    if sum(comp.values()) >= 2:
        pii = True
        redact_combinatorial(d, comp)
    return d, pii

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py input.csv")
        sys.exit(1)

    inp = sys.argv[1]
    outp = "redacted_output_candidate_full_name.csv"

    with open(inp, "r", encoding="utf-8") as f_in, open(outp, "w", encoding="utf-8", newline="") as f_out:
        reader = csv.DictReader(f_in)
        writer = csv.writer(f_out)
        writer.writerow(["record_id","redacted_data_json","is_pii"])
        for row in reader:
            rec_id = row["record_id"]
            try:
                data = json.loads(row["data_json"])  # <-- fixed case (data_json not Data_json)
            except:
                data = {}
            red, flag = process_record(data)
            writer.writerow([rec_id, json.dumps(red, separators=(",",":")), str(flag)])

if __name__ == "__main__":
    main()

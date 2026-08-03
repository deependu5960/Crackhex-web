import json
import time
import asyncio
import hashlib
import bcrypt
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from itertools import permutations
from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt, lmhash
from argon2 import PasswordHasher
from Crypto.Hash import MD4

from drupal_hash import verify_drupal_hash
from db import check_database_cache, save_to_database_cache

app = FastAPI(title="CrackHex Web API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class CrackRequest(BaseModel):
    hash_value: str
    algo: Optional[str] = None
    mode: int
    filter_type: Optional[int] = None
    pwd_len: Optional[int] = None
    prefix: Optional[str] = None
    custom_words: Optional[List[str]] = []

def verify_hash(algo: str, raw_passwd: str, target_hash: str) -> bool:
    try:
        algo = algo.upper()
        if algo == "MD5":
            return hashlib.md5(raw_passwd.encode()).hexdigest().lower() == target_hash.lower()
        elif algo == "SHA1":
            return hashlib.sha1(raw_passwd.encode()).hexdigest().lower() == target_hash.lower()
        elif algo == "SHA256":
            return hashlib.sha256(raw_passwd.encode()).hexdigest().lower() == target_hash.lower()
        elif algo == "SHA512":
            return hashlib.sha512(raw_passwd.encode()).hexdigest().lower() == target_hash.lower()
        elif algo == "BCRYPT":
            return bcrypt.checkpw(raw_passwd.encode("utf-8"), target_hash.encode("utf-8"))
        elif algo == "MD4":
            hsh = MD4.new()
            hsh.update(raw_passwd.encode())
            return hsh.hexdigest().lower() == target_hash.lower()
        elif algo == "NTLM":
            hsh = MD4.new()
            hsh.update(raw_passwd.encode("utf-16le"))
            return hsh.hexdigest().lower() == target_hash.lower()
        elif algo == "LM":
            return lmhash.verify(raw_passwd, target_hash.lower())
        elif algo == "MD5-CRYPT":
            return md5_crypt.verify(raw_passwd, target_hash)
        elif algo == "SHA256-CRYPT":
            return sha256_crypt.verify(raw_passwd, target_hash)
        elif algo == "SHA512-CRYPT":
            return sha512_crypt.verify(raw_passwd, target_hash)
        elif algo == "DRUPAL-7":
            return verify_drupal_hash(raw_passwd, target_hash)
        elif algo == "ARGON2":
            ph = PasswordHasher()
            ph.verify(target_hash, raw_passwd)
            return True
    except Exception:
        return False
    return False

def auto_identify_algo(target_hash: str) -> List[str]:
    h = target_hash.strip()
    if h.startswith(("$2a$", "$2b$", "$2y$")): return ["BCRYPT"]
    if h.startswith("$1$"): return ["MD5-CRYPT"]
    if h.startswith("$5$"): return ["SHA256-CRYPT"]
    if h.startswith("$6$"): return ["SHA512-CRYPT"]
    if h.startswith("$S$"): return ["DRUPAL-7"]
    if h.startswith(("$argon2i$", "$argon2d$", "$argon2id$")): return ["ARGON2"]
    
    if all(c in "0123456789abcdefABCDEF" for c in h):
        if len(h) == 32: return ["MD5", "NTLM", "LM", "MD4"]
        if len(h) == 40: return ["SHA1"]
        if len(h) == 64: return ["SHA256"]
        if len(h) == 128: return ["SHA512"]
    return []

async def crack_stream_generator(req: CrackRequest, http_request: Request):
    def send_event(status: str, msg: str, data: dict = None):
        payload = {"status": status, "message": msg, "data": data or {}}
        return f"data: {json.dumps(payload)}\n\n"

    target_hash = req.hash_value.strip()
    yield send_event("info", "Connecting to CrackHex API Stream...")
    
    # 1. Check DB Cache First
    cache_result = check_database_cache(target_hash)
    if cache_result.get("found"):
        plaintext = cache_result.get("plain_text")
        algo = cache_result.get("algo")
        yield send_event("success", f"Database match recovered.", {
            "plaintext": plaintext,
            "algo": algo,
            "cached": True
        })
        return

    # 2. Algo Resolution
    detected_algos = auto_identify_algo(target_hash)
    algo_to_use = req.algo.upper() if req.algo else (detected_algos[0] if len(detected_algos) == 1 else None)

    if not algo_to_use and len(detected_algos) > 1:
        yield send_event("error", f"Ambiguous algorithm. Candidates: {', '.join(detected_algos)}. Please specify manually.")
        return
    elif not algo_to_use:
        yield send_event("error", "Unable to auto-identify hash algorithm.")
        return

    yield send_event("info", f"Executing target evaluation using {algo_to_use}...")

    use_length = req.filter_type in [1, 3] and req.pwd_len is not None
    use_prefix = req.filter_type in [2, 3] and req.prefix is not None and req.prefix != ""

    def word_generator():
        if req.mode in [1, 3]:
            with open("rockyou.txt", "r", encoding="latin-1", errors="ignore") as f:
                for line in f:
                    word = line.strip()
                    if req.mode == 1:
                        if use_length and len(word) != req.pwd_len: continue
                        if use_prefix and not word.startswith(req.prefix): continue
                    yield word
        elif req.mode == 2:
            words = req.custom_words or []
            for i in range(1, len(words) + 1):
                for p in permutations(words, i):
                    candidate = "".join(p)
                    if use_length and len(candidate) != req.pwd_len: continue
                    if use_prefix and not candidate.startswith(req.prefix): continue
                    yield candidate

    # 3. Execution Crack Loop with Disconnect Check
    count = 0
    start_time = time.time()
    last_update_time = time.time()
    update_interval = 0.3  # Send update every 300ms for smooth UI
    
    for candidate in word_generator():
        # Check if the user clicked "Cancel" on the frontend
        if await http_request.is_disconnected():
            print("[*] Task aborted by user request.")
            return

        count += 1
        
        # Send progress update every 1,000 attempts OR every 300ms
        # This ensures smooth UI updates without overwhelming the system
        if count % 1000 == 0 or (time.time() - last_update_time) > update_interval:
            yield send_event("progress", f"Tested {count:,} combinations...")
            await asyncio.sleep(0.0001)
            last_update_time = time.time()

        if verify_hash(algo_to_use, candidate, target_hash):
            elapsed = round(time.time() - start_time, 2)
            yield send_event("success", f"Password found: {candidate}", {
                "plaintext": candidate,
                "algo": algo_to_use,
                "attempts": count,
                "time": elapsed
            })
            save_to_database_cache(target_hash, algo_to_use, candidate)
            return

    yield send_event("failed", "Exhausted all combinations. Password not found.")

@app.post("/api/crack")
async def start_cracking(req: CrackRequest, http_request: Request):
    return StreamingResponse(crack_stream_generator(req, http_request), media_type="text/event-stream")

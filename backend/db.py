import requests

# Paste your actual Vercel live URL here (without a trailing slash)
SERVER_URL = "https://crack-hex-server.vercel.app/"

def check_database_cache(hash_value):
    """Checks your Crack-Hex database via Server to see if the hash is already cracked."""
    try:
        response = requests.get(f"{SERVER_URL}/lookup", params={"hash_value": hash_value}, timeout=4)
        if response.status_code == 200:
            data = response.json()
            if data.get("found"):
                return data  # Returns {"found": True, "plain_text": "...", "algo": "..."}
    except Exception as e:
        print(f"\033[0;91m[*] Database cache bypass (Server offline or timeout)\033[0m ")
    return {"found": False}

def save_to_database_cache(hash_value, algo, plain_text):
    """Sends a newly cracked hash to your Crack-Hex database so you never have to crack it again."""
    try:
        payload = {
            "hash_value": hash_value,
            "algo": algo,
            "plain_text": plain_text
        }
        requests.post(f"{SERVER_URL}/store", json=payload, timeout=4)
        print("[+] Successfully saved hash mapping to central Crack-Hex DB!")
    except Exception as e:
        print(f"\033[0;91m[*] Failed to save to database cache\033[0m")

import hashlib

# Drupal 7 iterate count table mapping
ITERATION_TABLE = {
    'B': 8193,
    'C': 16385,
    'D': 32769,
    'E': 65537
}

def _drupal_custom_base64_encode(input_bytes, count):
    """Internal helper to encode raw bytes into Drupal 7's custom base64 string."""
    itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    output = ""
    i = 0

    while i < count:
        value = input_bytes[i]
        i += 1
        output += itoa64[value & 0x3F]

        if i < count:
            value |= input_bytes[i] << 8
        output += itoa64[(value >> 6) & 0x3F]

        if i >= count:
            break
        i += 1

        if i < count:
            value |= input_bytes[i] << 16
        output += itoa64[(value >> 12) & 0x3F]

        if i >= count:
            break
        i += 1

        output += itoa64[(value >> 18) & 0x3F]
        
    return output


def verify_drupal_hash(plain_password: str, target_hash: str) -> bool:
    """
    Verifies a plain text password against a target Drupal 7 hash string.
    Returns True if it matches, False otherwise.
    """
    # Defensive checks for malformed hashes
    if not target_hash or len(target_hash) < 12 or not target_hash.startswith("$S$"):
        return False
        
    algo_prefix = target_hash[:3]
    iterate_char = target_hash[3]
    salt = target_hash[4:12]

    # Handle cases where the hash uses an untracked iteration character
    if iterate_char not in ITERATION_TABLE:
        return False
        
    iterations = ITERATION_TABLE[iterate_char]

    # Core Algorithm Loop
    current_bytes = hashlib.sha512((salt + plain_password).encode('utf-8')).digest()
    passwd_bytes = plain_password.encode('utf-8')
    
    for _ in range(1, iterations):
        current_bytes = hashlib.sha512(current_bytes + passwd_bytes).digest()

    # Encode and reconstruct
    encoded_digest = _drupal_custom_base64_encode(current_bytes, len(current_bytes))[:43]
    computed_hash = f"{algo_prefix}{iterate_char}{salt}{encoded_digest}"

    return computed_hash == target_hash

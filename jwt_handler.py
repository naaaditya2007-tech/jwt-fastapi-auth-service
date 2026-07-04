import hmac, hashlib, base64, json, time

SECRET = b"super-secret-placement-key"

def create_jwt(payload: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = hmac.new(SECRET, f"{header}.{body}".encode(), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{header}.{body}.{sig_b64}"

def verify_jwt(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        expected = create_jwt(json.loads(base64.urlsafe_b64decode(parts[1] + "==")))
        return hmac.compare_digest(token, expected)
    except Exception:
        return False

if __name__ == "__main__":
    tok = create_jwt({"sub": "aditya", "exp": int(time.time()) + 3600})
    print("Generated Token:", tok)
    print("Valid Signature:", verify_jwt(tok))

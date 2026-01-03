import base64
import hashlib
import hmac
import struct
import time
import sys

def totp_sha512_10(userid: str, t: int | None = None) -> str:
    if t is None:
        t = int(time.time())
    counter = t // 30  # X=30, T0=0
    secret = (userid + "HENNGECHALLENGE004").encode("ascii")

    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret, msg, hashlib.sha512).digest()

    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset+4])[0] & 0x7FFFFFFF

    otp = code % (10**10)
    return f"{otp:010d}"

def basic_auth(userid: str, otp: str) -> str:
    token = f"{userid}:{otp}".encode("utf-8")
    return "Basic " + base64.b64encode(token).decode("ascii")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 totp_gen.py <email>", file=sys.stderr)
        sys.exit(1)
    email = sys.argv[1]
    otp = totp_sha512_10(email)
    print("OTP:", otp)
    print("Authorization:", basic_auth(email, otp))

if __name__ == "__main__":
    main()

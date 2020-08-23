import time
import base64
import hmac
import hashlib




def generate_code(shared_secret: str, timestamp: int = time.time()) -> str:
    timestamp = int(timestamp)

    hash_ = hmac.digest(
        key=base64.b64decode(shared_secret),
        msg=(timestamp // 30).to_bytes(8, byteorder='big'),
        digest=hashlib.sha1
        )

    b = hash_[19] & 0xF
    code_point = (hash_[b] & 0x7F) << 24 | (hash_[b + 1] & 0xFF) << 16 | (hash_[b + 2] & 0xFF) << 8 | (hash_[b + 3] & 0xFF)
    
    code = ''
    char_set = '23456789BCDFGHJKMNPQRTVWXY'
    for _ in range(5):
        code_point, i = divmod(code_point, len(char_set))
        code += char_set[i]

    return code

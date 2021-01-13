import rsa
import time
import hmac
import base64
import hashlib




def gen_publickey(rsa_modulus, rsa_exponent):
    return rsa.PublicKey(rsa_modulus, rsa_exponent)




def encode_password(password, publickey=None, rsa_modulus=None, rsa_exponent=None, as_string=False):

    if publickey is not None:
        pwd = base64.b64encode(rsa.encrypt(password.encode('UTF-8'), publickey))
    else:
        if rsa_modulus is not None and rsa_exponent is not None:
            pwd = base64.b64encode(rsa.encrypt(password.encode('UTF-8'), gen_publickey(rsa_modulus, rsa_exponent)))
        else:
            raise SyntaxError("You must set publickey or rsa_modulus and rsa_exponent.")

    if as_string:
        return pwd.decode("utf-8")
    return pwd




def gen_steam_guard_code(shared_secret: str, timestamp: int = time.time()) -> str:
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

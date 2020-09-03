import rsa
import base64




def generate_publickey(rsa_modulus, rsa_exponent):
    return rsa.PublicKey(rsa_modulus, rsa_exponent)




def encode_password(password, publickey=None, rsa_modulus=None, rsa_exponent=None, as_string=False):
    
    if publickey is not None:
        pwd = base64.b64encode(rsa.encrypt(password.encode('UTF-8'), publickey))
    else:
        if rsa_modulus is not None and rsa_exponent is not None:
            pwd = base64.b64encode(rsa.encrypt(password.encode('UTF-8'), generate_publickey(rsa_modulus, rsa_exponent)))
        else:
            raise SyntaxError("You must set publickey or rsa_modulus and rsa_exponent.")

    if as_string:
        return pwd.decode("utf-8")
    return pwd

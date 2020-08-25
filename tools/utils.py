import rsa
import base64




def generate_publickey(rsa_modulus, rsa_exponent):
    return rsa.PublicKey(rsa_modulus, rsa_exponent)




def encode_password(password, publickey = None, rsa_modulus = None, rsa_exponent = None):
    
    if publickey is not None:
        return base64.b64encode(rsa.encrypt(password.encode('UTF-8'), publickey))

    return base64.b64encode(rsa.encrypt(password.encode('UTF-8'), generate_publickey(rsa_modulus, rsa_exponent)))
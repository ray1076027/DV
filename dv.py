import hmac, hashlib, crypto
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class HMAC:
    def __init__(self,msg):
        self.msg = bytes(msg,'utf-8')

    def mac(self):
        self.key = secrets.token_bytes()
        tag = hmac.new(self.key, self.msg).hexdigest() #產生MAC的tag
        #紀錄密鑰
        with open('HMAC_key.pem','wb') as f:
            f.write(self.key)
        return tag

class PKE:
    def __init__(self,msg):
        self.msg = bytes(msg,'utf-8')
        #產生rsa pk,sk
        self.sk = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,
            backend=default_backend()
        )
        self.pk = self.sk.public_key()

    def encrypt(self):
        #加密
        ciphertext = self.pk.encrypt(
            self.msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

if __name__ == '__main__':
    msg = 'hellow'
    tag = HMAC(msg).mac()
    ciphertext = PKE(msg).encrypt().hex()
    print(tag,ciphertext)

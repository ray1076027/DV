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
        return tag,self.key
    def get_key(self):
        return self.key

class PKE:
    def __init__(self,msg):
        self.msg = bytes(msg,'utf-8')
        #產生rsa pk,sk
        self.sk = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.pk = self.sk.public_key()

    def encrypt(self):
        #加密
        self.ciphertext = self.pk.encrypt(
            self.msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return self.ciphertext

    def decrypt(self,ciphertext):
        #解密
        self.ciphertext = ciphertext
        self.plaintext = self.sk.decrypt(
            self.ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return self.plaintext.decode('utf-8')

class DS:
    def __init__(self,msg):
        self.msg = bytes(msg,'utf-8')
        self.sk = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.pk = self.sk.public_key()

    def sign(self):
        self.signature = self.sk.sign(
            self.msg,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return self.signature

    def verify(self, signature):
        self.signature = signature
        self.vrfy = self.pk.verify(
            self.signature,
            self.msg,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return self.vrfy

if __name__ == '__main__':
    msg = 'hellow'
    tag,mac_key = HMAC(msg).mac()
    pke = PKE(mac_key.hex())
    ciphertext = pke.encrypt()
    plaintext = pke.decrypt(ciphertext)
    #print(mac_key.hex() == plaintext)#check plaintext
    #print(tag)
    ds = DS(msg)
    sigma = ds.sign()
    vrfy = ds.verify(sigma)
    print(sigma.hex())
    print(vrfy)

import hmac, hashlib, crypto
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import time
import matplotlib.pyplot as plt

class HMAC:
    def __init__(self,msg):
        self.msg = msg

    def mac(self):
        self.key = secrets.token_bytes(32)
        tag = hmac.new(self.key, self.msg).hexdigest() #產生MAC的tag
        #紀錄密鑰
        with open('HMAC_key.pem','wb') as f:
            f.write(self.key)
        return tag,self.key
    def get_key(self):
        return self.key

class PKE:
    def __init__(self,msg):
        self.msg = msg
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
        self.msg = msg
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

    def verify(self, msg, signature, vk):
        self.sig = signature
        self.m = msg
        self.vk = vk
        self.vrfy = self.vk.verify(
            self.sig,
            self.m,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        try:
            if self.vrfy == None:
                return "valid"
        except:
            return "invalid"

class CRH:
    def __init__(self,m):
        self.msg = bytes(m, encoding='utf-8')
        self.sha256hash = hashlib.sha256(self.msg).digest()

    def hashvalue(self):
        return self.sha256hash
class run:
    def __init__(self,msg):
        self.msg = msg

    def run(self):
        stime=time.time()
        macstime = time.time()
        tag, mac_key = HMAC(self.msg).mac()
        macetime = time.time()
        macrtime = macetime - macstime
        mac_key_str = str(mac_key)
        pkestime = time.time()
        pke = PKE(mac_key)
        ciphertext = pke.encrypt()  # 將mac_key丟進public key encryption
        pkeetime = time.time()
        pkertime = pkeetime - pkestime
        print("c:", ciphertext.hex())
        # plaintext = pke.decrypt(ciphertext) #plaintext == mac_key
        # print("decryption check:",mac_key.hex() == plaintext)#check plaintext
        print("tag:", tag)
        hashstime = time.time()
        hash = CRH(mac_key_str).hashvalue()
        hashetime = time.time()
        hashrtime = hashetime - hashstime
        print("hash value:", hash.hex())
        dsstime = time.time()
        ds = DS(hash)
        sigma = ds.sign()
        dsetime = time.time()
        dsrtime = dsetime - dsstime
        vrfy = ds.verify(ds.msg, sigma, ds.pk)
        print("signatue:", sigma.hex())
        print("signature valid or not:", vrfy)
        etime = time.time()
        self.runtime = etime-stime
        print(f'run time: {etime - stime}, mac time: {macrtime}, pke time: {pkertime}, hash time: {hashrtime}, ds time: {dsrtime}')
        return dsrtime
if __name__ == '__main__':
    msg0 = secrets.token_bytes(32)
    msg1 = secrets.token_bytes(16)
    msg2 = secrets.token_bytes(8)
    msg3 = secrets.token_bytes(4)
    plt.plot([32,16,8],[run(msg0).run(), run(msg1).run(), run(msg2).run()])
    plt.ylabel('time')
    plt.xlabel('bytes')
    plt.legend()
    plt.show()

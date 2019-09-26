import os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import time
import filecmp

kB = 1024 # 1kB
with open('small_file.txt', 'wb') as f:
    f.write(os.urandom(kB))

mB = 10485760 # 1GB
with open('large_file.txt', 'wb') as f:
    f.write(os.urandom(mB))

Begin = time.time_ns()
code = 'FairyTail' #if there is no passphrase, private key is exported in clear
key = RSA.generate(2048)
encrypted_key = key.exportKey(passphrase=code, pkcs=8,protection="scryptAndAES128-CBC")
End = time.time_ns()
print("Key generation time: ",End-Begin," ns")

with open('private_rsa_key.pem', 'wb') as f:
    f.write(encrypted_key)
with open('public_rsa_key.pem', 'wb') as f:
    f.write(key.publickey().exportKey())

#################  Encrypt file  #################
def RSA_Enc(filename):
    with open('encrypted_data.txt', 'wb') as f:
        recipient_key = RSA.import_key(open('public_rsa_key.pem').read())
        session_key = get_random_bytes(16)

        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        f.write(cipher_rsa.encrypt(session_key))

        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        data = open(filename,'rb').read()

        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        f.write(cipher_aes.nonce)
        f.write(tag)
        f.write(ciphertext)

def RSA_Dec(filename):
    with open('encrypted_data.txt', 'rb') as i:
        private_key = RSA.import_key(open('private_rsa_key.pem').read(),passphrase=code)
        enc_session_key, nonce, tag, ciphertext = [i.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        with open('decrypted_data.txt','wb') as j:
            j.write(data)

Begin=time.time_ns()
RSA_Enc('small_file.txt')
End=time.time_ns()
print("Encryption time for 1 kb file: ",End-Begin," ns")
if End-Begin != 0:
    print("Encryption speed for 1 kb file: ",1024/(End-Begin),"bytes/ns")

Begin=time.time_ns()
RSA_Dec('small_file.txt')
End=time.time_ns()
print("Decryption time for 1 kb file: ",End-Begin," ns")
if End-Begin != 0:
    print("Decryption speed for 1 kb file: ",1024/(End-Begin),"bytes/ns")

print("The input file and decrypted file match: ", filecmp.cmp("small_file.txt", "decrypted_data.txt"))

Begin=time.time_ns()
RSA_Enc('large_file.txt')
End=time.time_ns()
print("Encryption time for 10 mb file: ",End-Begin," ns")
if End-Begin != 0:
    print("Encryption speed for 10 mb file: ",10485760/(End-Begin),"bytes/ns")

Begin=time.time_ns()
RSA_Dec('large_file.txt')
End=time.time_ns()
print("Decryption time for 10 mb file: ",End-Begin," ns")
if End-Begin != 0:
    print("Decryption speed for 10 mb file: ",10485760/(End-Begin),"bytes/ns")

print("The input file and decrypted file match: ", filecmp.cmp("large_file.txt", "decrypted_data.txt"))

exit()
#https://pycryptodome.readthedocs.io/en/latest/src/examples.html
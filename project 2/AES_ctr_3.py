import os
from Crypto.Cipher import AES
from Crypto import Random
import filecmp
from Crypto.Util import Counter
import time

kB = 1024  # 1kB
with open('small_file.txt', 'wb') as f:
    f.write(os.urandom(kB))

mB = 10485760 # 1GB
with open('large_file.txt', 'wb') as f:
    f.write(os.urandom(mB))

Begin = time.time_ns()
key = Random.get_random_bytes(32)
print("Key: ", key)
End = time.time_ns()
print("Key generation time: ",End-Begin," ns")

def aesEnc_CTR(filename):
    with open(filename, 'rb') as i:
        data = i.read()
        ctr=Counter.new(128)
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        ct=cipher.encrypt(data)
        with open("enc.txt", 'wb') as j:
            j.write(ct)

def aesDec_CTR(filename,sz):
    with open("enc.txt", 'rb') as i:
        data = i.read()
        ctr=Counter.new(128)
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        ct=cipher.decrypt(data)
        with open("dec.txt", 'wb') as j:
            j.write(ct)

#time in seconds
Begin = time.time_ns()
aesEnc_CTR("small_file.txt")
End = time.time_ns()
print("Encryption time for 1 kb file: ",End-Begin," ns")
if End-Begin != 0:
    print("Encryption speed for 1 kb file: ",1024/(End-Begin),"bytes/ns")


Begin = time.time_ns()
aesDec_CTR("enc.txt",0)
End = time.time_ns()
print("Decryption time for 1 kb file: ",End-Begin," ns")
if End-Begin != 0:
    print("Decryption speed for 1 kb file: ",1024/(End-Begin),"bytes/ns")

print("The input file and decrypted file match: ",filecmp.cmp("small_file.txt", "dec.txt"))

Begin = time.time_ns()
aesEnc_CTR("large_file.txt")
End = time.time_ns()
print("Encryption time for 10 mb file: ",End-Begin," ns")
if End-Begin != 0:
    print("Encryption speed for 10 mb file: ",10485760/(End-Begin),"bytes/ns")

Begin = time.time_ns()
aesDec_CTR("enc.txt",1)
End = time.time_ns()
print("Decryption time for 10 mb file: ",End-Begin," ns")
if End-Begin != 0:
    print("Decryption speed for 10 mb file: ",10485760/(End-Begin),"bytes/ns")

print("The input file and decrypted file match: ",filecmp.cmp("large_file.txt", "dec.txt"))

exit()



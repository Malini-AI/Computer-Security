import hashlib
import os
import time

kB = 1024 # 1kB
with open('small_file.txt', 'wb') as f:
    f.write(os.urandom(kB))

mB = 10485760 # 1GB
with open('large_file.txt', 'wb') as f:
    f.write(os.urandom(mB))


def SHA256(filename):
    h = hashlib.sha256()
    with open(filename, 'rb') as f:
        block = f.read(h.block_size)
        h.update(block)
        return h.hexdigest()

def SHA512(filename):
    h = hashlib.sha512()
    with open(filename, 'rb') as f:
        block = f.read(h.block_size)
        h.update(block)
        return h.hexdigest()

def SHA3_256(filename):
    h = hashlib.sha3_256()
    with open(filename, 'rb') as f:
        block = f.read(h.block_size)
        h.update(block)
        return h.hexdigest()

Begin=time.time_ns()
s1=SHA256('small_file.txt')
End=time.time_ns()
print("Time taken for  SHA256 with 1 kb file: ",End-Begin," ns")
if(End-Begin != 0):
    print("Hashing speed for 1 kb file: ",1024/(End-Begin),"bytes/ns")

Begin=time.time_ns()
s2=SHA512('small_file.txt')
End=time.time_ns()
print("Time taken for  SHA512 with 1 kb file: ",End-Begin," ns")
if(End-Begin != 0):
    print("Hashing speed for 1 kb file: ",1024/(End-Begin),"bytes/ns")

Begin=time.time_ns()
s3=SHA3_256('small_file.txt')
End=time.time_ns()
print("Time taken for  SHA3_256 with 1 kb file: ",End-Begin," ns")
if(End-Begin != 0):
    print("Hashing speed for 1 kb file: ",1024/(End-Begin),"bytes/ns")

Begin=time.time_ns()
l1=SHA256('large_file.txt')
End=time.time_ns()
print("Time taken for  SHA256 with 10 mb file: ",End-Begin," ns")
if(End-Begin != 0):
    print("Hashing speed for 10 mb file: ",10485760/(End-Begin),"bytes/ns")

Begin=time.time_ns()
l2=SHA512('large_file.txt')
End=time.time_ns()
print("Time taken for  SHA512 with 10 mb file: ",End-Begin," ns")
if(End-Begin != 0):
    print("Hashing speed for 10 mb file: ",10485760/(End-Begin),"bytes/ns")

Begin=time.time_ns()
l3=SHA3_256('large_file.txt')
End=time.time_ns()
print("Time taken for  SHA3_256 with 10 mb file: ",End-Begin," ns")
if(End-Begin != 0):
    print("Hashing speed for 10 mb file: ",10485760/(End-Begin),"bytes/ns")

with open('HashDigest.txt','w') as i:
    i.write(s1)
    i.write("\n")
    i.write(s2)
    i.write("\n")
    i.write(s3)
    i.write("\n")
    i.write(l1)
    i.write("\n")
    i.write(l2)
    i.write("\n")
    i.write(l3)

exit()
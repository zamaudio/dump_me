from Crypto.Util.number import bytes_to_long
from Crypto.Util import asn1
from Crypto.Hash import SHA256
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Signature import PKCS1_PSS
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5

keypair = RSA.generate(2048, e=17)

print keypair.publickey().exportKey()
print keypair.exportKey()

import struct, hashlib

def bytes2int(s, swap=True):
  num = 0L
  if swap: s = s[::-1]
  for c in s:
    num = num*256 + ord(c)
  return num

def bytearr2int(s):
	num = 0
	for b in s:
		num = num*256 + b
	return num

f = open("FTPR_part.bin", "rb")
hdr1 = f.read(0x80)
pubkey = bytes2int(f.read(0x100))
pubexp = bytes2int(f.read(0x4))
rsasig = bytes2int(f.read(0x100))

# header length
hlen = struct.unpack("<I", hdr1[4:8])[0] * 4
# manifest length
mlen = struct.unpack("<I", hdr1[0x18:0x1C])[0] * 4

# read trailer of the manifest
f.seek(hlen)
hdr2 = f.read(mlen-hlen)

h = SHA256.new()
h.update(hdr1)
h.update(hdr2)

mhash = bytes2int(h.digest(), False)
print "manifest hash:\n", hex(mhash)

n = keypair.n 
e = keypair.e 
d = keypair.d

message = bytearr2int(bytearray.fromhex("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003031300d060960864801650304020105000420"+hex(mhash)[2:-1]))

#cipher = PKCS1_v1_5.new(pk)
#ciphertext = cipher.encrypt(message+h.digest())
ciphertext = pow(message, d, n)

print "fake sig:\n",hex(ciphertext)
print "fake n:\n",hex(n) 

decfakesig = pow(ciphertext, e, n)

print "decrypted fake signature\n", hex(decfakesig)


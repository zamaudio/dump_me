from Crypto.Util.number import bytes_to_long
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
import sys

args=sys.argv
if len(sys.argv) == 1:
	print "Usage: python rsagen.py <me partition file>"
	sys.exit()	

keypair = RSA.generate(2048, e=17)

print "new user keys:"
print keypair.publickey().exportKey()
print keypair.exportKey()
print

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

p = open("padding", "rb")
padding = p.read(223)
p.close()

f = open(args[1], "rb")
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

mhash = h.digest()
print "manifest hash:\n", hex(bytes2int(mhash, False))
print
print "vendor signature:\n", hex(rsasig)
print
print "vendor modulus (n):\n", hex(pubkey)
print

n = keypair.n 
e = keypair.e 
d = keypair.d

message = bytes2int(padding+mhash, False)
ciphertext = pow(message, d, n)

print "user signature:\n", hex(ciphertext)
print
print "user modulus (n):\n", hex(n) 
print

decusersig = pow(ciphertext, e, n)
decvendorsig = pow(rsasig, 17, pubkey)

print "decrypted user signature using user pubkey:\n", hex(decusersig)
print
print "decrypted vendor signature using vendor pubkey:\n", hex(decvendorsig)
print
if decusersig == decvendorsig:
	print "Match!"
else:
	print "Failed"


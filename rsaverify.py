from Crypto.Util.number import bytes_to_long
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Signature import PKCS1_PSS
from Crypto import Random

filen = open("rsa_n2", "rb")
filee = open("rsa_e", "rb")
filesig = open("rsa_sig2", "rb")
fileraw = open("verifythis", "rb")

e = 17L
n = bytes_to_long(filen.read(0x100)[::-1])
sig = filesig.read(0x100)[::-1]

#length = 0x1b87f2
length = 0x25a000-0x958

offset = 0x0
#length = 0x20

filerevsig = open("rsa_sig2rev","wb")
filerevsig.write(sig)
filerevsig.close()

#f = open('wtf','r')
#key = RSA.importKey(f.read())

pubkey = RSA.construct((n,e))
print pubkey.publickey().exportKey()

verifier1 = PKCS1_v1_5.new(pubkey)
verifier2 = PKCS1_PSS.new(pubkey,saltLen=8)
verifier3 = PKCS1_PSS.new(pubkey,saltLen=1)
verifier4 = PKCS1_PSS.new(pubkey,saltLen=0)
verifier5 = PKCS1_PSS.new(pubkey,saltLen=20)

fileraw.seek(offset)
raw = fileraw.read(length)

digest = SHA256.new()
digest.update(raw)
print digest.hexdigest()

if verifier1.verify(digest, sig):
	print "Verified SHA256 PKCS1 1.5 OK"
if verifier2.verify(digest, sig):
	print "Verified SHA256 PSS_8 OK"
if verifier3.verify(digest, sig):
	print "Verified SHA256 PSS_1 OK"
if verifier4.verify(digest, sig):
	print "Verified SHA256 PSS_0 OK"
if verifier5.verify(digest, sig):
	print "Verified SHA256 PSS_20 OK"

'''
if verifier1.verify(digest1, sig):
	print "Verified SHA 1.5 OK"
if verifier2.verify(digest1, sig, saltlen=8):
	print "Verified SHA PSS OK"
if verifier1.verify(digest2, sig):
	print "Verified SHA224 1.5 OK"
if verifier2.verify(digest2, sig):
	print "Verified SHA224 PSS OK"
if verifier1.verify(digest3, sig):
	print "Verified SHA256 1.5 OK"
if verifier2.verify(digest3, sig):
	print "Verified SHA256 PSS OK"
if verifier1.verify(digest4, sig):
	print "Verified SHA384 1.5 OK"
if verifier2.verify(digest4, sig):
	print "Verified SHA384 PSS OK"
if verifier1.verify(digest5, sig):
	print "Verified SHA512 1.5 OK"
if verifier2.verify(digest5, sig):
	print "Verified SHA512 PSS OK"
'''

filen.close()
filee.close()
filesig.close()
fileraw.close()


from Crypto.Util.number import bytes_to_long
from Crypto.Hash import SHA256
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Signature import PKCS1_PSS
from Crypto import Random

filen = open("rsa_n", "rb")
filesig = open("rsa_sig", "rb")
fileraw = open("verifythis3", "rb")

e = 17L
#n = bytes_to_long(filen.read(0x100)[::-1])
n = bytes_to_long(filen.read(0x100))
#sig = filesig.read(0x100)[::-1]
sig = filesig.read(0x100)

#length = 0x25a000-0x958  #verifythis
#length = 0x25a000-0x890  #verifythis2
length = 0x25a000-0x284  #verifythis3
offset = 0x0

#filerevsig = open("rsa_sig2rev","wb")
#filerevsig.write(sig)
#filerevsig.close()

#f = open('wtf','r')
#key = RSA.importKey(f.read())

pubkey = RSA.construct((n,e))
print pubkey.publickey().exportKey()

verifier1 = PKCS1_v1_5.new(pubkey)
verifier2 = PKCS1_PSS.new(pubkey,saltLen=8)
verifier3 = PKCS1_PSS.new(pubkey,saltLen=1)
verifier4 = PKCS1_PSS.new(pubkey,saltLen=0)
verifier5 = PKCS1_PSS.new(pubkey,saltLen=20)
verifier6 = PKCS1_PSS.new(pubkey,saltLen=17)

fileraw.seek(offset)
raw = fileraw.read(length)

digest = SHA256.new(raw)

print "Digest: "+digest.hexdigest()

sha1digest = SHA1.new(digest.hexdigest())

if verifier1.verify(digest, sig):
	print "Verified SHA1+SHA256 PKCS1 1.5 OK"
if verifier2.verify(digest, sig):
	print "Verified SHA1+SHA256 PSS_8 OK"
if verifier3.verify(digest, sig):
	print "Verified SHA1+SHA256 PSS_1 OK"
if verifier4.verify(digest, sig):
	print "Verified SHA1+SHA256 PSS_0 OK"
if verifier5.verify(digest, sig):
	print "Verified SHA1+SHA256 PSS_20 OK"
if verifier6.verify(digest, sig):
	print "Verified SHA1+SHA256 PSS_17 OK"

filen.close()
filesig.close()
fileraw.close()


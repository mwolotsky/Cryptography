import socket
from OpenSSL import SSL
import sys
from Crypto.PublicKey import RSA,DSA
import RSA1280,DSA1024
from Crypto.Util import asn1

context = SSL.Context(SSL.SSLv23_METHOD)
context.use_privatekey_file('key')
context.use_certificate_file('cert')

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sock = SSL.Connection(context,sock)
sock.bind(('',5000))
sock.listen(5)

(connection,address) = sock.accept()
while True:
    received = repr(connection.recv(65535))
    print "*" * 80
    list = received.split(" ")
    print "Received Ciphertext and Signature"
    ciphertext = str(list[0])
    ciphertext = ciphertext.replace("\\n","\n")
    ciphertext = ciphertext.replace("'","")
    signature = list[1] + list[2]
    signature = signature.replace("\'","")
    signature = signature.replace(",",", ")
    
    print "Ciphertext:\n%s" % ciphertext
    print "Signature:\n{}".format(signature)
    try:
        file = open("PublicDSAKey.pem","r")
        inkey = file.read()
        file.close()
    except:
        print "DSA Public Key of Sender Not Found" 
        sys.exit()
    print "DSA Public Key of Sender Found:\n%s" % inkey
    
    seq = asn1.DerSequence()
    data = "\n".join(inkey.strip().split("\n")[1:-1]).decode("base64")
    seq.decode(data)
    p,q,g,y = seq[1:]
    
    sig = []
    for s in signature.split(","):
        sig.append(long(s.strip("()")))
    signature = tuple(sig)
    DSAPublic = DSA.construct((y,g,p,q))
    auth = DSA1024.verifyMessage(DSAPublic, ciphertext, signature)
    if auth:
        print "The Signature Has Been Verified"
    else:
        print "The Signature Could Not Be Verified"
        sys.exit()
    try:
        file = open("PrivateRSAKey.pem","r")
        inkey = file.read()
        file.close()
    except:
        print "RSA Private Key of Receiver Not Found"    
        sys.exit()
    print "RSA Private Key of Receiver Found:\n%s" % inkey
    RSAPrivate = RSA.importKey(inkey)
    plaintext = RSA1280.RSA_Decrypt(ciphertext, RSAPrivate) 
    print "The Plaintext Value Has Been Deciphered:\n%s" % plaintext
    sock.close()
    print "*" * 80
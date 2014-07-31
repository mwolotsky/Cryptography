import socket
import sys
import RSA1280
import DSA1024
from Crypto.PublicKey import RSA
from Crypto.PublicKey import DSA
from Crypto.Util import asn1
def prompt() :
    sys.stdout.write('<SSL Cryptographic Messenger> ')
    sys.stdout.flush()

RSA1280.exportKeys()
DSA1024.exportKeys()        
sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

try:
    sock.connect(("localhost",5000))
except:
    print "Unable to Connect"
    sys.exit()
    
sslSocket = socket.ssl(sock)
print "Connected to SSL Communication Server. Start Sending Messages"
prompt()

while True:
    message = sys.stdin.readline()
    print "*" * 80
    try:
        file = open("PublicRSAKey.pem","r")
        inkey = file.read()
        file.close()
    except:
        print "Public RSA Key Not Found"
        sys.exit()
    RSAPublic = RSA.importKey(inkey)
    print "RSA Public Key of Recipient Found:\n%s" % inkey
    ciphertext = RSA1280.RSA_Encrypt(message,RSAPublic)
    print "Message Has Been Encrypted with RSA Public Key of Recipient:\n%s" % ciphertext
    try:
        file = open("PrivateDSAKey.pem","r")
        inkey = file.read()
        file.close()
    except:
        print "Private DSA Key Not Found"
        sys.exit()
    print "DSA Private Key of Sender Found:\n%s" % inkey
    
    seq = asn1.DerSequence()
    data = "\n".join(inkey.strip().split("\n")[1:-1]).decode("base64")
    seq.decode(data)
    p,q,g,y,x = seq[1:]
    DSAPrivate = DSA.construct((y,g,p,q,x))
    signature = DSA1024.signMessage(DSAPrivate, ciphertext)
    
    print "Signature Generated from Ciphertext:\n{}".format(signature)
    print "Ciphertext and Signature are Sent"
    sslSocket.write("{} {}".format(ciphertext,signature))
    print "*" * 80
    prompt()
sock.close()

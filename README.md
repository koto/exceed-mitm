Exceed onDemand (EoD) is a dependable managed application access solution
designed for enterprises. It offers pixel perfect drawing, low cost
scalability and trusted security access over any network connection.

Vulnerabilities are present in the current version of the software:

 - Product URL: http://connectivity.opentext.com/products/exceed-ondemand.aspx
 - Product Name: **OpenText Exceed OnDemand 8**
 - Client version: <= **13.8.3.497**
 - Server version: <= **13.8.3.521**

Credits
=====
  - Slawomir Jasek `<Slawomir dot Jasek at securing dot pl>`
  - Krzysztof Kotowicz `<kkotowicz at securing dot pl>`

Dates
=====
 - 18.11.2013 - Vendor disclosure
 - 21.11.2013 - Additional vulnerabilities found & reported to vendor 
 - 21.11.2013 - Vendor acknowledges the report, "no further details to share"
 - 06.12.1013 - Query about issue resolution & initial public disclosure date, vendor ignores
 - 16.12.2013 - Full disclosure

Authentication bypass due to protocol downgrade (CVE-2013-6806)
===============================================================

Summary 
-------
If communication between EoD Client and Cluster Manager can be intercepted and tampered with (e.g. by using ARP poisoning/DNS hijacking/rogue access point), EoD Client can be forced to using older authentication protocol, sending out credentials in the clear.

Details
-------
Upon connecting to Cluster Manager (TCP port 5500), EoD Client sends 4 bytes: `\x01\x01\x00\x00`, in turn CM responds with 4 bytes, negotiating the version of the protocol to use. Response from current CM version is : `\x0b\x00\x00\x00`. This triggers SSL handshake (similar to STARTSSL mechanism), credentials are then sent in encrypted SSLv3 connection:

Wireshark dump of the beginning of connection:

    00000000  01 01 00 00                                      ....
        00000000  0b 00 00 00                                      ....
    00000004  16 03 00 00 6d 01 00 00  69 03 00 52 8d e8 02 cf ....m... i..R....
    00000014  88 d3 96 14 f4 a3 7c 47  f3 0d 85 57 58 d6 c9 f7 ......|G ...WX...
    00000024  18 24 95 15 2e 05 82 27  b7 1e ff 00 00 42 00 3a .$.....' .....B.:
    00000034  00 39 00 38 00 35 00 34  00 33 00 32 00 2f 00 1b .9.8.5.4 .3.2./..
    00000044  00 1a 00 19 00 18 00 17  00 16 00 15 00 14 00 13 ........ ........
    00000054  00 12 00 11 00 0a 00 09  00 08 00 07 00 06 00 05 ........ ........
    00000064  00 04 00 03 c0 19 c0 18  c0 17 c0 16 c0 15 00 ff ........ ........
    00000074  01 00                                            ..

(16 03 ... bytes initiate SSL connection) 

However, if the attacker modifies the response, sending e.g. `\x01\x01\x00\x00`, client will send credentials in the clear without establishing SSL connection first:

    00000000  01 01 00 00                                      ....
        00000000  01 01 00 00                                      ....
    00000004  11 01 30 0d 08 03 f1 00  00 00 00 00 00 00 00 00 ..0..... ........
    00000014  00 ff ff 7f 00 00 01 ac  3d 08 08 68 69 6a 61 63 ........ =..hijac
    00000024  6b 65 64 0a 30 35 31 45  31 45 31 41 32 36 00 01 ked.051E 1E1A26..

Exemplary bytes sent right after the 8-bytes handshake contain user login and obfuscated password. In standard connection, the same packet is sent within SSL stream.

We did not try to use Kerberos-based authentication protocol, but the attack against that will most likely be identical (instead of credentials the Kerberos ticket will be sent in the clear).

Access conditions
---------------------------
Man-in-the-middle attacker

Impact
----------
Credentials disclosure, authentication bypass

Proof of Concept
------------------------
`exceed-downgrade.py` script can be used to test for and exploit that vulnerability.

Recommendation
-------------------------
Do not allow servers to downgrade a protocol in EoD Client communication. Always require that the credentials are sent in encrypted channel.

More info
-------------
  - CWE-757: Selection of Less-Secure Algorithm During Negotiation
('Algorithm Downgrade') - http://cwe.mitre.org/data/definitions/319.html
  - http://en.wikipedia.org/wiki/Opportunistic_encryption


Man in the Middle vulnerability (CVE-2013-6807)
============================================

Summary 
-------
If communication between EoD Client and Cluster Manager can be intercepted and tampered with (e.g. by using ARP poisoning/DNS hijacking/rogue access point), communication over SSL channel can be man-in-the-middled due to using anonymous SSL ciphers.

Details
-------
Current version of EoD client when connecting to server side components, establishes encrypted SSL connection (with the exception of connecting to EoD Proxy, for which SSL encryption is optional and turned off by default). In SSL `ClientHello` message EoD client advertises several anonymous ciphers. In their default configuration EoD servers choose one of advertised anonymous SSL ciphers for encryption `SSL_DH_anon_WITH_AES_256_CBC_SHA`.

    $ sudo ssldump -d -i eth1 tcp port 5500
    New TCP connection #1: [redacted](43426) <-> eod.opentext.com(5500)
    0.1783 (0.1783)  C>S
    ---------------------------------------------------------------
    01 01 00 00                                        ....
    ---------------------------------------------------------------

    0.3480 (0.1697)  S>C
    ---------------------------------------------------------------
    0b 00 00 00                                        ....
    ---------------------------------------------------------------

    1 1  0.3483 (0.0003)  C>S  Handshake
          ClientHello
            Version 3.0 
            cipher suites
            SSL_DH_anon_WITH_AES_256_CBC_SHA
            SSL_DHE_RSA_WITH_AES_256_CBC_SHA
            SSL_DHE_DSS_WITH_AES_256_CBC_SHA
            SSL_RSA_WITH_AES_256_CBC_SHA
            SSL_DH_anon_WITH_AES_128_CBC_SHA
            SSL_DHE_RSA_WITH_AES_128_CBC_SHA
            SSL_DHE_DSS_WITH_AES_128_CBC_SHA
            SSL_RSA_WITH_AES_128_CBC_SHA
            SSL_DH_anon_WITH_3DES_EDE_CBC_SHA
            SSL_DH_anon_WITH_DES_CBC_SHA
            SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA
            SSL_DH_anon_WITH_RC4_128_MD5
            SSL_DH_anon_EXPORT_WITH_RC4_40_MD5
            SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA
            SSL_DHE_RSA_WITH_DES_CBC_SHA
            SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
            SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA
            SSL_DHE_DSS_WITH_DES_CBC_SHA
            SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
            SSL_RSA_WITH_3DES_EDE_CBC_SHA
            SSL_RSA_WITH_DES_CBC_SHA
            SSL_RSA_EXPORT_WITH_DES40_CBC_SHA
            SSL_RSA_WITH_IDEA_CBC_SHA
            SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5
            SSL_RSA_WITH_RC4_128_SHA
            SSL_RSA_WITH_RC4_128_MD5
            SSL_RSA_EXPORT_WITH_RC4_40_MD5
            Unknown value 0xc019
            Unknown value 0xc018
            Unknown value 0xc017
            Unknown value 0xc016
            Unknown value 0xc015
            Unknown value 0xff
            compression methods
                      NULL
    1 2  0.4896 (0.1412)  S>C  Handshake
          ServerHello
            Version 3.0 
            session_id[32]=
              70 23 26 fb 1c a5 eb c3 28 62 d6 e1 85 41 7e 49 
              cf bd 69 35 26 de e3 a7 0b 3c f8 be 0a 84 8b a2 
            cipherSuite         SSL_DH_anon_WITH_AES_256_CBC_SHA
            compressionMethod                   NULL

Anonymous ciphers do not transfer any server certificate. As a consequence, client has no way of authenticating the server - as noted by RFC 3268:

>   1. ADH provides confidentiality but not authentication.  This means
>     that (if authentication is required) the communicating parties
>      must authenticate to each other by some means other than TLS.
>
>   2. ADH is vulnerable to man-in-the-middle attacks, as a consequence
>      of the lack of authentication.  The parties must have a way of
>     determining whether they are participating in the same TLS
>      connection.  If they are not, they can deduce that they are under
>      attack, and presumably abort the connection.

Man-in-the-middle attacker can establish two SSL connections - one with EoD client, one with OnDemand server side components and be able to eavesdrop and tamper with the data being exchanged.

Exceed Connection Server Administrator’s Guide (v13.8)
http://connectivity.opentext.com/hostedmedia/Documentation/EoD_8/Manuals/ExceedConnectionServer.pdf, page 64 (About SSL features) mentions using anonymous ciphers by default, however it does not describe the risk associated:

>  By default, Exceed Connection Server uses anonymous authentication.
>  Connections to Exceed Connection Server always use SSL encryption. No
>  additional configuration is necessary. 

Instead, it provides administrator with the option to set up server's certificate:

>  When using ciphersuites that use the Digital Signature Standard (DSS), the
>  Client verifies the identity of the server before establishing an
>  SSL-encrypted session. For verification, the server needs a private key file
>  and a certificate file. 

Our investigation shows that this does not provide any form of protection at all.
During standard connection, if the server provides the client with appropriate certicate and chooses non-anonymous cipher, client correctly validates the certificate and displays the warning when if differs with the one stored during the first-time connection. However, during the man-in-the-middle attack EoD client connects to attacker's SSL server instead, still offering anonymous cipher as an option. Attacker server may choose this cipher and the client will accept the connection, ignoring the certicate stored during previous connection attempts. This scenario has been tested by us with full success.

Current setup allows for transparent man-in-the-middle attacks for all connections to ECS and ESC proxies, even those using SSL FIPS mode. The attacker can observe and tamper any traffic betwen EoD client and those servers.

Access conditions
------------------
Ability to intercept and modify the TCP traffic between EoD client and ECS servers

Impact
------
Credentials disclosure, authentication bypass, lack of connections' confidentiality and integrity

Proof of concept
------------------------
`exceed-mitm.py` script can be used to test for and exploit that vulnerability.
    
    $ python exceed-mitm.py --dump eod.opentext.com

Connecting the client through this mitm proxy (e.g. by hijacking DNS entries) will reveal cleartext communication between the client and the server.

Advisory
--------
Do not advertise anonymous ciphers in EoD client when establishing SSL connections. Disallow anonymous ciphers in EoD server side components (OpenSSL cipher setting: !aNULL). SSL connections must be based on authenticated ciphers, server certificate generation should be enforced during installation instead of being provided as an option.

More info
----------
  - CWE-923: Improper Authentication of Endpoint in a Communication Channel - http://cwe.mitre.org/data/definitions/923.html
  - CWE-300: Channel Accessible by Non-Endpoint ('Man-in-the-Middle') - http://cwe.mitre.org/data/definitions/300.html
  - RFC 6101: http://tools.ietf.org/html/rfc6101
  - RFC 3268: http://www.ietf.org/rfc/rfc3268.txt
  - http://en.wikipedia.org/wiki/Opportunistic_encryption

Use of password obfuscation (CVE-2013-6805)
===========================================

Summary
-------
Application uses trivial password obfuscation mechanism in various places


Details
-------
Authentication message (in various versions of the protocol being transferred in-the-clear or in SSL connection) contains an obfuscated password, which can be trivially decoded by the attacker observing the transmission. The same password obfuscation mechanism is being used when storing connection parameters in eod8 files, allowing the attacker who gets access to eod8 files to retrieve the original passwords.

The algorithm used is:

  1. reverse the bytes of given password
  2. XOR each byte with bytes of `Hummingbird Communications Limited` string.
  3. return hex-asccii encoding of XORed password

To retrieve the original password, the algorithm need to be reversed, e.g.:

    pwd = 0200102C
    rpwd = 2C 10 00 02
    "Humm" = 48 75 6d 6d
    "Humm" XOR rpwd = 'demo'

Access conditions
-----------------
Man in the middle / Access to eod8 files

Impact
------
Credentials disclosure

Proof of concept
------------------------
`exceed-mitm.py` script can be used to test for and exploit that vulnerability.
    
    $ python exceed-mitm.py --dump eod.opentext.com

Connecting client through this proxy will deobfuscate all credentials being sent. 

Advisory
--------
In authentication protocol, consider establishing a challenge-response handshake to disallow revealing the password during man-in-the middle attacks and protect from replay attacks, where the attacker replies the authentication message without knowing the password. This can also be mitigated by using proper SSL ciphers and enforcing SSL communication. Passwords should not be stored in trivially reversible form in eod8 files, consider storing encrypted passwords with an installation-unique or user-provided key instead.

More info:
----------
- CWE-261: Weak Cryptography for Passwords - http://cwe.mitre.org/data/definitions/261.html
- CWE-319: Cleartext Transmission of Sensitive Information - http://cwe.mitre.org/data/definitions/319.html


Session hijacking (CVE 2013-6994)
=================================

Summary
-------
Application sends unique session identificators in cleartext, allowing
the attacker eavesdropping TCP traffic between EoD client to hijack the authenticated user session. This happens also if proxy server has enabled SSL encryption for connections.

Details
-------
EoD connection handshaking relies on three TCP connections. First connection authenticates the user in Cluster Manager (this is SSL encrypted). Second connection (also SSL encrypted) provides the client with session id - 20 bytes alphanumeric identificator. Third TCP connection is with EoD Proxy. This connection is by default unencrypted as mentioned in Exceed Connection Server Administrator’s Guide (v13.8) - http://connectivity.opentext.com/hostedmedia/Documentation/EoD_8/Manuals/ExceedConnectionServer.pdf, page 64 (About SSL features):

  The option to enable SSL encryption for proxy
  connections is not enabled by default. If you want to secure all
  session communications (not just server log in), see “Configuring
  Cluster Settings” on page 18.

However, even if the connection switches to SSL negotiation, session identifier is sent in plaintext before the SSL handshake begins. Therefore it is possible to read the authenticated session identifier even without decrypting SSL traffic.

Example: Beginning of the proxy server traffic:

    00000000  04 01 00 00                                      ....
        00000000  09 00 00 00                                      ....
    00000004  4c 41 39 30 34 46 36 43  31 35 45 30 35 32 38 44 LA904F6C 15E0528D
    00000014  45 36 32 43                                      E62C

`LA904F6C15E0528DE62C` is the session id sent in clear text.

Using this session identifier the atttacker can connect to EoD proxy server directly, skipping the authentication part.

Our investigation shows that the session hijack has to occur during a short time-window. Within a few seconds from obtaining the session id, original user must be disconnected (e.g. by changing his session id in-traffic to a dummy one) and his session id must be used by the attacker. We were able to prepare a proof-of-concept where two simultaneous connections were made with EoD server with separate EoD clients, their session identifiers were read from the clear text traffic and switched. As a result, users got each other's sessions. 

Access conditions
-----------------
Ability to eavesdrop and modify TCP traffic between EoD client and EoD Proxy

Impact
------
Session hijacking

Proof of concept
------------------------
`exceed-mitm.py` script can be used to test for and exploit that vulnerability.
    
    $ python exceed-mitm.py --nossl --hijack eod.opentext.com

Above command will wait for two simultaneous connections and switch their sessions. 

Advisory
--------
SSL encryption of proxy connection should be enabled by default. Protocol needs to be changed to send session id in encrypted part of the connections.

More info
---------
  - CWE-523: Unprotected Transport of Credentials - http://cwe.mitre.org/data/definitions/523.html
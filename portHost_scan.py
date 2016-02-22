#! /usr/bin/env python

import scapy.config
import scapy.layers.l2
import scapy.route
import socket
import nmap
import math
import os


def do_portscan(target_ip):
    nm = nmap.PortScanner()
    nm.scan(target_ip, '22-443')
    scan = nm[target_ip]

    for protocol in scan.all_protocols():

        open_ports = scan[protocol].keys()
        print '      found %d open %s ports: ' % (len(open_ports),
                                                  protocol)
        for port in open_ports:
            info = scan[protocol][port]
            print "        %4d: %s (%s %s): %s" % (port,
                                                   info['name'],
                                                   info['product'],
                                                   info['version'],
                                                   info['extrainfo'])


def ddn2cidr(bytes_network, bytes_netmask):
    network = scapy.utils.ltoa(bytes_network)
    netmask = 32 - int(round(math.log(0xFFFFFFFF - bytes_netmask, 2)))
    return "%s/%s" % (network, netmask)


if os.geteuid() != 0:
    exit("You need to have root privileges to run this script ...")

# get routes of active interface
routes = filter(
    lambda x: x[3] == scapy.config.conf.iface,
    scapy.config.conf.route.routes)

# filter out loopback/localhost and broadcast
routes = filter(lambda x: x[0] != 0 and x[1] !=
                0xFFFFFFFF and x[1] > 0, routes)

# filter out zeroconf (?), 2851995648 => 169.254.0.0/16
routes = filter(lambda x: x[0] != 2851995648, routes)

print '[*] found', len(routes), 'networks via', scapy.config.conf.iface, ':'
for network, netmask, _, interface, address in routes:
    net = ddn2cidr(network, netmask)
    print '[*]  ', net

for network, netmask, _, _, _ in routes:
    net = ddn2cidr(network, netmask)
    print '\n[*] scanning network', net, '...',

    try:
        ans, unans = scapy.layers.l2.arping(
            net, iface=interface, timeout=1, verbose=False)
    except:
        pass
    for host in ans:
        resp = host[1]
        hostname = socket.gethostbyaddr(resp.psrc)[0]
        print "\n    HOST %s == %-16s (%s)" % (resp.src, resp.psrc, hostname)
        do_portscan(resp.psrc)

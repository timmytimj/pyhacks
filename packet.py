#!/usr/bin/env python

from scapy_ext.igmp import *

def send_v3_report(myint="eth0"):
    """ My attempt ... --Jocke"""
    a = Ether()
    b = IP()
    b.src = "1.2.3.4"
    c = IGMP()
    c.type = 0x22                 # v3 Report
    c.numgrp = 2
    e = IGMPv3Group()
    e.rtype = 4                   # "Join" -- Change to Exclude
    e.maddr = "225.1.2.1"
    f = IGMPv3Group()
    f.rtype = 4                   # "Join" -- Change to Exclude
    f.maddr = "225.1.2.4"
    if c.igmpize(b, a):
        d = a/b/c/e/f
        print "Sending a properly formatted IGMPv3 Membership Report: two groups ..."
        sendp(d, iface=myint)
        d.show()
        d.show2()
        d.mysummary()
    else:
        print "Invalid IGMP packet"
    return

def send_v2_report(myint="eth0"):
    """ My attempt ... --Jocke"""
    a = Ether()
    b = IP()
    b.src = "1.2.3.4"
    c = IGMP()
    c.type = 0x16                 # v2 Join
    c.gaddr = "225.1.2.3"
    if c.igmpize(b, a):
        d = a/b/c
        print "Sending a properly formatted IGMPv2 Join ..."
        sendp(d, iface=myint)
        d.show()
        d.show2()
        d.mysummary()
    else:
        print "Invalid IGMP packet"
    return

#test_igmp()
#test_igmpv3()

send_v3_report()
send_v2_report()


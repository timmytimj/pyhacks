"""
Scapy class for IGMP (Internet Group Membership Protocol) version 2 and 3

Copyright (C) David Sips      <gator@broadcom.com>
Copyright (C) Joachim Nilsson <troglobit@gmail.com>

This class is heavily based on the ground work by David Sips, in
issue http://bb.secdev.org/scapy/issue/31/ -- reworked by Joachim
for Scapy 2.2.0 and cut down to only hanle pure IGMP v2/v3 msgs.

For information on the IGMP v2/v3 protocol, see:
- http://www.iana.org/assignments/igmp-type-numbers
- https://tools.ietf.org/html/rfc2236
- https://tools.ietf.org/html/rfc3376

You are free to use and modify this under the GNU GPLv2 license
"""

from scapy.all import *

def is_valid_mcaddr(addr):
  """Verify that addr is in range 224.0.0.0 -- 239.255.255.255"""
  byte = atol(addr) >> 24 & 0xFF
  return byte >= 224 and byte <= 239


class IGMPv3Group(Packet):
  """IGMP Group Record for IGMPv3 Membership Report

  This class is derived from class Packet and should be concatenated to
  an instantiation of class IGMP. Within the IGMP instantiation, the
  numgrp element will need to be manipulated to indicate the proper
  number of group records.

  """
  name = "IGMPv3Group"
  igmpv3grtypes = { 1 : "Mode Is Include",
                    2 : "Mode Is Exclude",
                    3 : "Change To Include Mode",
                    4 : "Change To Exclude Mode",
                    5 : "Allow New Sources",
                    6 : "Block Old Sources"}

  fields_desc = [ ByteEnumField("rtype", 1, igmpv3grtypes),
                      ByteField("auxdlen", 0),
                  FieldLenField("numsrc", None, "srcaddrs"),
                        IPField("maddr", "0.0.0.0"),
                 FieldListField("srcaddrs", None, IPField("sa", "0.0.0.0"), "numsrc")
  ]
  show_indent = 0


  def post_build(self, p, pay):
    """Called implicitly before a packet is sent."""
    p += pay
    if self.auxdlen != 0:
      print "      NOTICE: A properly formatted and complaint V3 Group Record should have an"
      print "              Auxiliary Data length of zero (0)."
      print "              Subsequent Group Records are lost!"
    return p


  def mysummary(self):
    """Display a summary of the IGMPv3 group record."""
    return self.sprintf("IGMPv3 Group Record %IGMPv3gr.type% %IGMPv3gr.maddr%")


class IGMP(Packet):
  """IGMP v2/v3 Message Class

  This class is derived from class Packet. 

  The fields defined below are a direct interpretation of the v3
  Membership Query Message.  Fields 'type' through 'qqic' are directly
  assignable.  For 'numsrc', do not assign a value.  Instead add to the
  'srcaddrs' list to auto-set 'numsrc'. To assign values to 'srcaddrs',
  use the following methods:

    c = IGMPv3()
    c.srcaddrs = ['1.2.3.4', '5.6.7.8']
    c.srcaddrs += ['192.168.10.24']

  At this point, 'c.numsrc' is three (3)

  'chksum' is automagically calculated before the packet is sent.

  'mrcode' is also the Advertisement Interval field

  """
  name = "IGMPv3"
  igmpv3types = { 0x11 : "IGMP v2/v3 Membership Query",
                  0x16 : "Version 2  Membership Report (Join)",
                  0x17 : "Version 2  Membership Report (Leave)",
                  0x22 : "Version 3  Membership Report"
  }

  fields_desc = [                   ByteEnumField("type", 0x11, igmpv3types),
                                        ByteField("mrcode", 0),                                           # Only for pkt.type == 0x11, reserved otherwise
                                      XShortField("chksum", None),
                  ConditionalField(       IPField("gaddr", "0.0.0.0"),                                   lambda pkt: pkt.type != 0x22), # For 0x11, 0x16 and 0x17
                  ConditionalField(      BitField("resv", 0, 4),                                         lambda pkt: pkt.type == 0x11),
                  ConditionalField(      BitField("s",    0, 1),                                         lambda pkt: pkt.type == 0x11),
                  ConditionalField(      BitField("qrv", 0, 3),                                          lambda pkt: pkt.type == 0x11),
                  ConditionalField(     ByteField("qqic",0),                                             lambda pkt: pkt.type == 0x11),
                  ConditionalField( FieldLenField("numsrc",   None, "srcaddrs"),                         lambda pkt: pkt.type == 0x11),
                  ConditionalField(FieldListField("srcaddrs", None, IPField("sa", "0.0.0.0"), "numsrc"), lambda pkt: pkt.type == 0x11),
                  ConditionalField(    ShortField("reserved", None),                                     lambda pkt: pkt.type == 0x22),
                  ConditionalField(    ShortField("numgrp", 0),                                          lambda pkt: pkt.type == 0x22)
  ]


  def float_encode(self, value):
    """Convert the integer value to its IGMPv3 encoded time value if needed.

    If value < 128, return the value specified. If >= 128, encode as a
    floating point value. Value can be 0 - 31744.

    """
    if value < 128:
      code = value
    elif value > 31743:
      code = 255
    else:
      exp     = 0
      value >>= 3

      while value > 31:
        exp    += 1
        value >>= 1

      exp <<= 4
      code  = 0x80 | exp | (value & 0x0F)
    return code


  def post_build(self, p, pay):
    """Called implicitly before a packet is sent to compute and place IGMPv3 checksum.

    Parameters:
      self    The instantiation of an IGMPv3 class
      p       The IGMPv3 message in hex in network byte order
      pay     Additional payload for the IGMPv3 message
    """
    p += pay
    if self.type in [0, 0x31, 0x32, 0x22]:   # for these, field is reserved (0)
      p = p[:1]+chr(0)+p[2:]
    if self.chksum is None:
      ck = checksum(p)
      p = p[:2]+chr(ck>>8)+chr(ck&0xff)+p[4:]
    return p


  def mysummary(self):
    """Display a summary of the IGMPv3 object."""

    if isinstance(self.underlayer, IP):
      return self.underlayer.sprintf("IGMPv3: %IP.src% > %IP.dst% %IGMPv3.type% %IGMPv3.gaddr%")
    else:
      return self.sprintf("IGMPv3 %IGMPv3.type% %IGMPv3.gaddr%")


  def igmpize(self, ip=None, ether=None):
    """Called to explicitely fixup associated IP and Ethernet headers

    Parameters:
      self    The instantiation of an IGMP class.
      ip      The instantiation of the associated IP class.
      ether   The instantiation of the associated Ethernet.

    Returns:
      True    The tuple ether/ip/self passed all check and represents
               a proper IGMP packet.
      False   One of more validation checks failed and no fields
               were adjusted.

    The function will examine the IGMP message to assure proper format.
    Corrections will be attempted if possible. The IP header is then
    properly adjusted to ensure correct formatting and assignment. The
    Ethernet header is then adjusted to the proper IGMP packet format.

    """

    # The rules are:
    #   1.  ttl = 1 (RFC 2236, section 2)
    #  igmp_binds = [ (IP, IGMP,   { "proto": 2 , "ttl": 1 }),
    #   2.  tos = 0xC0 (RFC 3376, section 4)
    #               (IP, IGMPv3, { "proto": 2 , "ttl": 1, "tos":0xc0 }),
    #               (IGMPv3, IGMPv3gr, { }) ]
    # The rules are:
    #   1.  the Max Response time is meaningful only in Membership Queries and
    #       should be zero otherwise (RFC 2236, section 2.2)

    if (self.type != 0x11):         #rule 1
      self.mrtime = 0

    if (self.adjust_ip(ip) == True):
      if (self.adjust_ether(ip, ether) == True): return True
    return False


  def adjust_ether (self, ip=None, ether=None):
    """Called to explicitely fixup an associated Ethernet header

    The function adjusts the ethernet header destination MAC address
    based on the destination IP address.

    """
    # The rules are:
    #   1. send to the group mac address address corresponding to the IP.dst
    if ip != None and ip.haslayer(IP) and ether != None and ether.haslayer(Ether):
      iplong = atol(ip.dst)
      ether.dst = "01:00:5e:%02x:%02x:%02x" % ( (iplong>>16)&0x7F, (iplong>>8)&0xFF, (iplong)&0xFF )
      return True
    return False


  def adjust_ip (self, ip=None):
    """Called to explicitely fixup an associated IP header

    The function adjusts the IP header based on conformance rules and
    the group address encoded in the IGMP message.

    The rules are:
    1. Send General Group Query to 224.0.0.1 (all systems)
    2. Send Leave Group to 224.0.0.2 (all routers)
    3a.Otherwise send the packet to the group address
    3b.Send reports/joins to the group address
    4. ttl = 1 (RFC 2236, section 2)
    5. send the packet with the router alert IP option (RFC 2236, section 2)

    """
    if ip and ip.haslayer(IP):
      if self.type == 0x11:
        if self.gaddr == "0.0.0.0":
          ip.dst = "224.0.0.1"                   # IP rule 1
          result = True
        elif is_valid_mcaddr(self.gaddr):
          ip.dst = self.gaddr                    # IP rule 3a
          result = True
        else:
          print "Warning: Using invalid Group Address"
          result = False

      elif (self.type == 0x12 or self.type == 0x16 or self.type == 0x22):
          if self.type == 0x22:                  # IGMP v3 report
            ip.dst = "224.0.0.22"
            result = True
          elif is_valid_mcaddr(self.gaddr):
            ip.dst = self.gaddr                  # IP rule 3b
            result = True
          else:
            print "Warning: Invalid or no IGMP Group Address set"
            result = False

      elif self.type == 0x17 and is_valid_mcaddr(self.gaddr):
          ip.dst = "224.0.0.2"                   # IP rule 2
          result = True

      else:
        print "Warning: Using invalid IGMP Type"
        result = False

    else:
      print "Warning: Not an IP packet!"
      result = False

    if result == True:
       ip.ttl = 1                                # IP Rule 4
       ip.options = [IPOption_Router_Alert()]    # IP rule 5

    return result

bind_layers( IP,          IGMP,        frag=0, proto=2, ttl=1, tos=0xc0)
bind_layers( IGMP,        IGMPv3Group, frag=0, proto=2)
bind_layers( IGMPv3Group, IGMPv3Group, frag=0, proto=2)

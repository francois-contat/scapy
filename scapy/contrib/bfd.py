# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# Copyright (C) 2019 Francois Contat <francois.contat@ssi.gouv.fr>

# Based on BFD RFC 5880 https://tools.ietf.org/html/rfc5880

# scapy.contrib.description = The Bidirectional Forwarding Detection
# scapy.contrib.status = loads

# Start dev

import struct
import hashlib

from scapy.packet import Packet, bind_layers, Raw
from scapy.fields import ByteEnumField, ByteField, IntField, ShortField
from scapy.fields import IPField, IP6Field, StrLenField, FlagsField
from scapy.fields import FieldLenField
from scapy.fields import StrFixedLenField, ShortEnumField
from scapy.layers.inet import TCP, UDP
from scapy.compat import orb


VERSION = 1
DIAGNOSTIC = {0: 'No Diagnostic',
              1: 'Control Detection Time expired',
              2: 'Echo Function Failed',
              3: 'Neighbor Signald Session Down',
              4: 'Forwarding Plane Reset',
              5: 'Path Down',
              6: 'Concatenated Path Down',
              7: 'Administratively Down',
              8: 'Reverse Concatenated Path Down'}
              # 9-31 Reserved for future use
STATE = {0: 'AdminDown',
         1: 'Down',
         2: 'Init',
         3: 'Up'}

AUTH_TYPE = {0: 'Reserved',
             1: 'Simple Password',
             2: 'Keyed MD5',
             3: 'Meticulous Keyed MD5',
             4: 'Keyed SHA1',
             5: 'Meticulous Keyed SHA1'}
             # 6-255 Reserved for future use

class BFD(Packet):
    '''
    Generic BFD Control packet from section 4.1
    https://tools.ietf.org/html/rfc5880#section-4.1
    '''

    name = 'BFD Control Packet'
    fields_desc = [BitField('Version', 1, 3),
                   BitEnumField('Diagnostic', 0, 5, DIAGNOSTIC),
                   BitEnumField('State', 0, 2, STATE),
                   BitField('Poll', 0, 1),
                   BitField('Final', 0, 1),
                   BitField('Control_Plane_Independant', 0, 1),
                   BitField('Authentication_Present', 0, 1),
                   BitField('Demand', 0, 1),
                   BitField('Multipoint', 0, 1),
#old                   FlagsField("Flags", 0b000000, 6, ["Poll", "Final",
#                              "Control Plane Independent",
#                              "Authentication Present",
#                              "Demand",
#                              "Multipoint"]),
                   ByteField('Detect_mult', 0),
                   ByteField('Length', 24),
                   IntField('My_discriminator', 1),
                   IntField('Your_discriminator', 1),
                   IntField('Desired_Min_TX_Interval', 1),
                   IntField('Required_Min_TX_Interval', 1),
                   IntField('Required_Min_Echo_RX_Interval', 1)]

    def guess_payload_class(self, payload):
        if self.Authentication_Present and 1 <= orb(payload[0]) < len(AUTH_TYPE):
            return AUTH_TYPE[orb(payload[0])]
        #return BFDAuth

    def post_build(self, pkt, pay):
        temp_len = len(pkt)
        if not self.Length:
            pkt = pkt[:3] + struct.pack('!B', temp_len + 4) + pkt[4:]
        if pkt.Authentication_Present == 2: # Keyed MD5
            hashed = hashlib.md5(pkt)
        #elif pkt.Authentication_Present == 3 # Meticulous Keyed MD5
        #elif pkt.Authentication_Present == 4 # Keyed SHA1
        #elif pkt.Authentication_Present == 5 # Meticulous Keyed SHA1
        return pkt + pay

class SimplePassword(Packet):
    '''
    Simple password authentication section from section 4.2
    https://tools.ietf.org/html/rfc5880#section-4.2
    '''

    name = 'Simple password'
    fields_desc = [ByteField('Auth_Type', 1),
                   ByteField('Auth_Len', None),
                   ByteField('Auth_Key_ID', 0),
                   StrField('Password', '')]

# TODO hash = Tout le paquet bfd+entete auth+mdp pad de \x00 sur 20 octets
# exemple : pkt2 = rdpcap('bfd-auth-sha1.pcap')[164]
# del(pkt2[3].Auth_Key_Digest)
# hashed = hashlib.sha1()
# hashed.update(raw(pkt2[3]))
# hashed.update(b'test'+b'\x00' * 16)
# hashed.digest().hex()

class KeyedMD5(Packet):
    '''
    Keyed MD5 authentication section from section 4.3
    https://tools.ietf.org/html/rfc5880#section-4.3
    '''

    name = 'Keyed MD5'
    fields_desc = [ByteField('Auth_Type', 2),
                   ByteField('Auth_Len', None),
                   ByteField('Auth_Key_ID', 0),
                   ByteField('Reserved', ''),
                   IntField('Sequence_Number', 1),
                   StrField('Auth_Key_Digest', '')]


class MeticulousKeyedMD5(Packet):
    '''
    Meticulous Keyed MD5 authentication section from section 4.3
    https://tools.ietf.org/html/rfc5880#section-4.3
    '''

    name = 'Meticulous Keyed MD5'
    fields_desc = [ByteField('Auth_Type', 3),
                   ByteField('Auth_Len', None),
                   ByteField('Auth_Key_ID', 0),
                   ByteField('Reserved', ''),
                   IntField('Sequence_Number', 1),
                   StrField('Auth_Key_Digest', '')]


class KeyedSHA1(Packet):
    '''
    Keyed SHA1 authentication section from section 4.4
    https://tools.ietf.org/html/rfc5880#section-4.4
    '''

    name = 'Keyed SHA1'
    fields_desc = [ByteField('Auth_Type', 4),
                   ByteField('Auth_Len', None),
                   ByteField('Auth_Key_ID', 0),
                   ByteField('Reserved', ''),
                   IntField('Sequence_Number', 1),
                   StrField('Auth_Key_Digest', '')]


class MeticulousKeyedSHA1(Packet):
    '''
    Meticulous Keyed SHA1 authentication section from section 4.4
    https://tools.ietf.org/html/rfc5880#section-4.4
    '''

    name = 'Meticulous Keyed SHA1'
    fields_desc = [ByteField('Auth_Type', 5),
                   ByteField('Auth_Len', None),
                   ByteField('Auth_Key_ID', 0),
                   ByteField('Reserved', ''),
                   IntField('Sequence_Number', 1),
                   StrField('Auth_Key_Digest', '')]



AUTH_TYPE ={1: SimplePassword,
            2: KeyedMD5,
            3: MeticulousKeyedMD5,
            4: KeyedSHA1,
            5: MeticulousKeyedSHA1}

class BFDAuth(Packet):

    '''
    Dummy BFD Authentication packet in case there is an optional auth section
    eg. https://tools.ietf.org/html/rfc5880#section-4.1
    '''
    name = 'BFDAuth'

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        '''
          Attribution of correct aithentication type depending on pdu_type
        '''
        if _pkt and len(_pkt) >= 2:
            auth_type = orb(_pkt[0])
            if 1 <= auth_type <= 5:
                return AUTH_TYPE[auth_type]
        return Raw



bind_layers(TCP, BFD, dport=3784)  # BFD
bind_layers(TCP, BFD, sport=3784)  # BFD
bind_layers(UDP, BFD, dport=3784)  # BFD
bind_layers(UDP, BFD, sport=3784)  # BFD
bind_layers(TCP, BFD, dport=3785)  # BFD-Control
bind_layers(TCP, BFD, sport=3785)  # BFD-Control
bind_layers(UDP, BFD, dport=3785)  # BFD-Control
bind_layers(UDP, BFD, sport=3785)  # BFD-Control

if __name__ == '__main__':
    from scapy.main import interact
    interact(mydict=globals(), mybanner='BFD')

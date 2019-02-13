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

# Based on SSH RFC 4251 https://www.ietf.org/rfc/rfc4251.txt

# scapy.contrib.description = Secure Shell protocol
# scapy.contrib.status = loads

# Data types :
#   byte : 8-bit value.
#   boolean : 0=FALSE, 1=TRUE
#   uint32 : unsigned 32-bit int 
#   uint64 : unsigned 64-bit int 
#   string : arbitrary length binary string. Terminating null character are not
#   used mpint : multiple precision integers store as string (8bit per byte)
#               MSB first. Negative has value 1 as the most significant bit of 
#               the first byte of data
#   name-list : string contining comma-separated list of names

# Start dev

import struct

from scapy.packet import Packet, bind_layers, Raw
from scapy.fields import StrField, StrLenField, IntField, FieldLenField
from scapy.fields import ByteField, StrFixedLenField
from scapy.compat import orb

#from scapy.fields import ByteEnumField, ByteField, IntField, ShortField
#from scapy.fields import IPField, IP6Field, StrLenField
#from scapy.fields import FieldLenField
#from scapy.fields import StrFixedLenField, ShortEnumField
#from scapy.layers.inet import TCP

COMPRESSION = {0: "none",
               1: "zlib"}

# TODO : faire les longueurs
HMAC_LENGTH = {'sha1': 20}

CIPHER = {0:0}

SSH_MESSAGE = {1:'disconnect',
               2:'ignore',
               3:'unimplemented',
               4:'debug',
               5:'service_request',
               6:'service_accept',
               20:'kexinit',
               21:'newkeyx'}

#STATIC_END_OF_DATA_V1_LENGTH = 24
#
#RTR_VERSION = {0: '0',
#               1: '1'}
#
#ERROR_LIST = {0: 'Corrupt Data',
#              1: 'Internal Error',
#              2: 'No data Available',
#              3: 'Invalid Request',
#              4: 'Unsupported Protocol Version',
#              5: 'Unsupported PDU Type',
#              6: 'Withdrawal of Unknown Record',
#              7: 'Duplicate Announcement Received',
#              8: 'Unexpected Protocol Version'}
#
#
#class RTRErrorReport(Packet):
#
#    '''
#
#    Error Report packet from section 5.10
#    https://tools.ietf.org/html/rfc6810#section-5.10
#
#    '''
#    name = 'Error Report'
#    fields_desc = [ByteEnumField('rtr_version', 0, RTR_VERSION),
#                   ByteEnumField('pdu_type', 10, PDU_TYPE),
#                   ShortEnumField('error_code', 0, ERROR_LIST),
#                   IntField('length', None),
#                   FieldLenField('length_of_encaps_PDU',
#                                 None, fmt='!I', length_of='erroneous_PDU'),
#                   StrLenField('erroneous_PDU', '',
#                               length_from=lambda x: x.length_of_encaps_PDU),
#                   FieldLenField('length_of_error_text', None, fmt='!I',
#                                 length_of='error_text'),
#                   StrLenField('error_text', '',
#                               length_from=lambda x: x.length_of_error_text)]
#
#    def post_build(self, pkt, pay):
#        temp_len = len(pkt) + 2
#        if not self.length:
#            pkt = pkt[:2] + struct.pack('!I', temp_len) + pkt[6:]
#        return pkt + pay

class SSHBinaryPacket(Packet):
    '''
        Generic Binary SSH packet
        https://tools.ietf.org/html/rfc4253#section-6
    '''
    name = 'SSH Generic Binary'
    fields_desc = [IntField('packet_length', 16),
                   FieldLenField('padding_length', 0, fmt='B', length_of ='padding'),
                   StrLenField('payload', '', length_from = lambda x: x.packet_length - x.padding_length - 1),
                   StrLenField('padding', '', length_from = lambda x: x.padding_length),
                   StrLenField('mac', '')] # TODO : length a calculer selon le cipher choisi (super...)

    # note : length of the concatenation of 'packet_length', 'padding_length', 'payload', and 'random padding' MUST be a multiple of the cipher block size or 8, whichever is larger


class SSHKeyExchange(Packet):
    '''
        SSH Key Exchange packet
        https://tools.ietf.org/html/rfc4253#section-7.1
    '''
    name = 'SSH Key Exchange'
    fields_desc = [IntField('packet_length', 16),
                   FieldLenField('padding_length', 0, fmt='B', length_of ='padding'),
                   ByteEnumField('message', 20, SSH_MESSAGE),
                   StrFixedLenField('cookie', b'\x00'*16, 16),
                   FieldLenField('kex_algorithms_length', 0, fmt='I', length_of='kex_algorithms'),
                   StrLenField('kex_algorithms', '', length_from = lambda x:x.kex_algorithms_length),
                   FieldLenField('server_host_key_algorithms_length', 0, fmt='I', length_of='server_host_key_algorithms'),
                   StrLenField('server_host_key_algorithms', '', length_from = lambda x:x.server_host_key_algorithms_length),
                   FieldLenField('encryption_algorithms_client_to_server_length', 0, fmt='I', length_of='encryption_algorithms_client_to_server'),
                   StrLenField('encryption_algorithms_client_to_server', '', length_from = lambda x:x.encryption_algorithms_client_to_server_length),
                   FieldLenField('encryption_algorithms_server_to_client_length', 0, fmt='I', length_of='encryption_algorithms_server_to_client'),
                   StrLenField('encryption_algorithms_server_to_client', '', length_from = lambda x:x.encryption_algorithms_server_to_client_length),
                   FieldLenField('mac_algorithms_client_to_server_length', 0, fmt='I', length_of='mac_algorithms_client_to_server'),
                   StrLenField('mac_algorithms_client_to_server', '', length_from = lambda x:x.mac_algorithms_client_to_server_length),
                   FieldLenField('mac_algorithms_server_to_client_length', 0, fmt='I', length_of='mac_algorithms_server_to_client'),
                   StrLenField('mac_algorithms_server_to_client', '', length_from = lambda x:x.mac_algorithms_server_to_client_length),
                   FieldLenField('compression_algorithms_client_to_server_length', 0, fmt='I', length_of='compression_algorithms_client_to_server'),
                   StrLenField('compression_algorithms_client_to_server', '', length_from = lambda x:x.compression_algorithms_client_to_server_length),
                   FieldLenField('compression_algorithms_server_to_client_length', 0, fmt='I', length_of='compression_algorithms_server_to_client'),
                   StrLenField('compression_algorithms_server_to_client', '', length_from = lambda x:x.compression_algorithms_server_to_client_length),
                   FieldLenField('languages_client_to_server_length', 0, fmt='I', length_of='languages_client_to_server'),
                   StrLenField('languages_client_to_server', '', length_from = lambda x:x.languages_client_to_server_length),
                   FieldLenField('languages_server_to_client_length', 0, fmt='I', length_of='languages_server_to_client'),
                   StrLenField('languages_server_to_client', '', length_from = lambda x:x.languages_server_to_client_length),
                   ByteField('first_kex_packet_follows', 0),
                   IntField('reserved', 0),
                   StrLenField('padding', '', length_from = lambda x: x.padding_length)]



class SSHVersionExchange(Packet):
    '''
        SSH Version Exchange packet
        https://tools.ietf.org/html/rfc4253#section-4.2
    '''
    name = 'SSH Version Exchange'
    fields_desc = [FieldListField('comments', ['SSH-2.0-scapySSH_1.0\x0d\x0a'], StrStopField('version', None, b"\x0d\x0a", 0))] 


class SSH(Packet):
    '''
        Dummy SSH packet for SSH dissection
        https://tools.ietf.org/html/rfc4253
    '''
    name = 'SSH'

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        '''
          Dispatching the packet to the correct type
        '''
        if len(_pkt) >= 4:
            if ''.join(map(str, struct.unpack('cccc', _pkt[:4]))) == 'SSH-':
                return SSHVersionExchange
            elif len(_pkt) >= 5:
                if orb(_pkt[5]) == 20:
                    return SSHKeyExchange
        return SSHBinaryPacket


bind_layers(TCP, SSH, dport=22)  # reserved port
bind_layers(TCP, SSH, sport=22)  # reserved port

if __name__ == '__main__':
    from scapy.main import interact
    interact(mydict=globals(), mybanner='RPKI to Router')

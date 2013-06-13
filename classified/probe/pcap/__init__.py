# Python imports
import os
import struct

# Project imports 
from classified.probe.base import Probe


class PCAP(Probe):
    magic = 0xa1b2c3d4
    format = '{filename_relative}[{line:d}]: pcap v{version} ({linktype})'
    header = 'IHHiIII'
    header_size = struct.calcsize(header)
    linktype = {
        0:   'NULL',
        1:   'Ethernet',
        3:   'AX25',
        6:   'IEEE802.5',
        7:   'ARCNet BSD',
        8:   'SLIP',
        9:   'PPP',
        10:  'FDDI',
        50:  'PPP HDLC',
        51:  'PPP ETHER',
        100: 'ATM RFC1483',
        101: 'RAW',
        104: 'C_HDLC',
        105: 'IEEE802.11',
        107: 'FRELAY',
        108: 'LOOP',
        113: 'LINUX SLL',
        114: 'LTALK',
        117: 'PFLOG',
        119: 'IEEE802.11 PRISM',
        122: 'IP over FC',
        123: 'SUNATM',
        127: 'IEEE802.11 RADIOTAP',
        129: 'ARCNET Linux',
        138: 'Apple IP over IEEE1394',
        139: 'MTP2 with PHDR',
        140: 'MTP2',
        141: 'MTP3',
        142: 'SCCP',
        143: 'DOCSIS',
        144: 'Linux IRDA',
        163: 'IEEE802.11 AVS',
        165: 'BACNET MS TP',
        166: 'PPP PPPD',
        169: 'GPRS LLC',
        177: 'Linux LAPD',
        187: 'Bluetooth HCI H4',
        189: 'USB Linux',
        192: 'PPI',
        195: 'IEEE802.15-4',
        196: 'SITA',
        197: 'ERF',
        201: 'Bluetooth HCI H4 with PHDR',
        202: 'AX25 KISS',
        203: 'LAPD',
        204: 'PPP with DIR',
        205: 'C_HDLC with DIR',
        206: 'FRELAY with DIR',
        209: 'IPMB Linux',
        215: 'IEEE802.15-4 NONASK PHY',
        220: 'USB Linux mmapped',
        224: 'FC 2',
        225: 'FC 2 with frame delims',
        226: 'IPNET',
        227: 'CAN SOCKETCAN',
        228: 'IPv4',
        229: 'IPv6',
        230: 'IEEE802.15-4 NOFCS',
        231: 'DBUS',
        235: 'DVB CI',
        236: 'MUX27010',
        237: 'STANAG 5066-D PDU',
        239: 'NFLOG',
        240: 'Netanalyzer',
        241: 'Netanalyzer Transparent',
        242: 'IPOIB',
        243: 'MPEG-2 TS',
        244: 'NG40',
        245: 'NFC LLCP',
        247: 'Infiniband',
        248: 'SCTP',
    }

    def probe(self, item):
        item.open('r')
        chunk = item.read(self.header_size)
        if len(chunk) != self.header_size:
            return

        magic, version_major, version_minor, thiszone, \
            sigfigs, snaplen, network = struct.unpack(self.header, chunk)

        if magic == self.magic:
            self.record(item,
                line=1,
                version='%d.%d' % (version_major, version_minor),
                version_major=version_major,
                version_minor=version_minor,
                linktype=self.linktype.get(network, 'Unknown'),
            )

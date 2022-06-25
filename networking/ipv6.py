import struct

from general import *

class IPv6:

    def __init__(self, raw_data):
        self.version = raw_data[0] >> 4
        self.traffic_class = ((raw_data[0] & 15) << 4) + (raw_data[1] >> 4)
        self.flow_label = self.__get_flow_label(raw_data)
        self.payload_length, self.next_header, self.hop_limit = struct.unpack(
            '! H B B', raw_data[4:8]
        )
        self.source_address = self.__get_address(raw_data[8:24])
        self.destination_address = self.__get_address(raw_data[24:40])

    def __get_flow_label(self, raw_data):
        flow_label = ((raw_data[1] & 15) << 8) + raw_data[2]
        return (flow_label << 8) + raw_data[3]

    def __get_address(self, raw_data):
        address = ":".join(map('{:04x}'.format, struct.unpack('! H H H H H H H H', raw_data)))
        return address.replace(":0000:","::" ).replace(":::", "::").replace(":::", "::")

    def ipv6(self, addr):
        return '.'.join(map(str, addr))
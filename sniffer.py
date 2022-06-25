import socket
import os
import time

from general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP
from networking.ipv6 import IPv6

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

PROTOCOL_ALL = 0
PROTOCOL_IPV4 = 8
PROTOCOL_IPV6 = 56710

FILTER_OPTIONS = {
    0: PROTOCOL_ALL,
    1: PROTOCOL_IPV4,
    2: PROTOCOL_IPV6
}

def start_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')

        filter_option = int(
            input(
                'Escolha o protocolo:\n' +
                '0 - Todos\n' +
                '1 - IPv4\n' +
                '2 - IPv6\n\n'
            )
        )

        if filter_option not in FILTER_OPTIONS:
            print('Opção inválida. Tente novamente.\n')
            time.sleep(1)            
        else:
            filter_option = FILTER_OPTIONS[filter_option]
            break

    return filter_option

def show_frame_ipv4(eth):
    ipv4 = IPv4(eth.data)
    print(TAB_1 + 'IPv4 Packet:')
    print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
    print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

    # ICMP
    if ipv4.proto == 1:
        icmp = ICMP(ipv4.data)
        print(TAB_1 + 'ICMP Packet:')
        print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
        print(TAB_2 + 'ICMP Data:')
        print(format_multi_line(DATA_TAB_3, icmp.data))

    # TCP
    elif ipv4.proto == 6:
        tcp = TCP(ipv4.data)
        print(TAB_1 + 'TCP Segment:')
        print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
        print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
        print(TAB_2 + 'Flags:')
        print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
        print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

        if len(tcp.data) > 0:
            # HTTP
            if tcp.src_port == 80 or tcp.dest_port == 80:
                print(TAB_2 + 'HTTP Data:')
                try:
                    http = HTTP(tcp.data)
                    http_info = str(http.data).split('\n')
                    for line in http_info:
                        print(DATA_TAB_3 + str(line))
                except:
                    print(format_multi_line(DATA_TAB_3, tcp.data))
            else:
                print(TAB_2 + 'TCP Data:')
                print(format_multi_line(DATA_TAB_3, tcp.data))

    # UDP
    elif ipv4.proto == 17:
        udp = UDP(ipv4.data)
        print(TAB_1 + 'UDP Segment:')
        print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))

    # Other IPv4
    else:
        print(TAB_1 + 'Other IPv4 Data:')
        print(format_multi_line(DATA_TAB_2, ipv4.data))

def show_frame_ipv6(eth):
    ipv6 = IPv6(eth.data)
    print(TAB_1 + 'IPv6 Packet:')
    print(TAB_2 + 'Version: {}, Traffic Class: {}, Flow Label: {},'.format(ipv6.version, ipv6.traffic_class, ipv6.flow_label))
    print(TAB_2 + 'Payload Length: {}, Next Header: {}, Hop Limit: {}'.format(ipv6.payload_length, ipv6.next_header, ipv6.hop_limit))
    print(TAB_2 + 'Source Address: {}, Destination Address: {}'.format(ipv6.source_address, ipv6.destination_address))

def show_frame(eth):
    print('Ethernet Frame:')
    print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

    if eth.proto == PROTOCOL_IPV4:
        show_frame_ipv4(eth)
    elif eth.proto == PROTOCOL_IPV6:
        show_frame_ipv6(eth)
    else:
        print('Ethernet Data:')
        print(format_multi_line(DATA_TAB_1, eth.data))

def main():
    filter_option = start_menu();

    pcap = Pcap('capture.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)
        eth = Ethernet(raw_data)

        if filter_option == PROTOCOL_IPV4 and eth.proto != PROTOCOL_IPV4:
            continue
        elif filter_option == PROTOCOL_IPV6 and eth.proto != PROTOCOL_IPV6:
            continue

        show_frame(eth)

        input("\nPrecione enter para obter o próximo pacote...\n")

    pcap.close()

main()
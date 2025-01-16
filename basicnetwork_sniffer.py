import socket
import struct
import textwrap


def main():
    conn =socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        raw_data, addr =conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))



#unpack ethernet frame
def ethernet_frame(data):
    # unpack first 14 bytes
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    # return all data after that
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(proto), data[14:]

#return properly formatted mac
def get_mac_address(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return  ':'.join(bytes_str).upper()

main()
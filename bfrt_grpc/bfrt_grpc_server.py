
from bfrt_grpc_helper import BfRtAPI
import binascii
import socket

def ip_to_int(ip):
    return int(binascii.hexlify(socket.inet_aton(ip)),16)

def mask_to_int(mask):
    return int(binascii.hexlify(socket.inet_aton(mask)),16)

class Bfrt_GRPC_Server:
    def __init__(self):
        self.bfrt = BfRtAPI(client_id=1)
        self.installed_flow_key = set()
    
    def print_tables_info(self):
        return self.bfrt.print_tables_info()

    def print_table_info(self, table_name):
        return self.bfrt.print_table_info(table_name)
    
    def dump_table(self, table_name):
        return self.bfrt.dump_table(table_name)

    def tcp_flow_add_with_drop(self, src_ip, dst_ip, src_port, dst_port):
        match_key = (src_ip, dst_ip, src_port, dst_port, 'tcp')
        if match_key in self.installed_flow_key:
            return 0
        else:
            print(f"Adding flow: {match_key}, already installed flow number: {len(self.installed_flow_key)}")
            self.installed_flow_key.add(match_key)
            self.bfrt.entry_add(table_name='pipe.Ingress.tcp_flow', 
                                keys=[('hdr.ipv4.src_addr', ip_to_int(src_ip), ip_to_int('255.255.255.255')),
                                    ('hdr.ipv4.dst_addr', ip_to_int(dst_ip), ip_to_int('255.255.255.255')),
                                    ('hdr.tcp.src_port', src_port), 
                                    ('hdr.tcp.dst_port', dst_port)],
                                data=[],
                                action_name='Ingress.drop')
            return 0
    
    def udp_flow_add_with_drop(self, src_ip, dst_ip, src_port, dst_port):
        match_key = (src_ip, dst_ip, src_port, dst_port, 'udp')
        if match_key in self.installed_flow_key:
            return 0
        else:
            print(f"Adding flow: {match_key}, already installed flow number: {len(self.installed_flow_key)}")
            self.bfrt.entry_add(table_name='pipe.Ingress.udp_flow', 
                                keys=[('hdr.ipv4.src_addr', ip_to_int(src_ip), ip_to_int('255.255.255.255')),
                                    ('hdr.ipv4.dst_addr', ip_to_int(dst_ip), ip_to_int('255.255.255.255')),
                                    ('hdr.udp.src_port', src_port), 
                                    ('hdr.udp.dst_port', dst_port)],
                                data=[],
                                action_name='Ingress.drop')
            return 0
    
    def icmp_flow_add_with_drop(self, src_ip, dst_ip):
        match_key = (src_ip, dst_ip, 'icmp')
        if match_key in self.installed_flow_key:
            return 0
        else:
            print(f"Adding flow: {match_key}, already installed flow number: {len(self.installed_flow_key)}")
            self.bfrt.entry_add(table_name='pipe.Ingress.icmp_flow', 
                                keys=[('hdr.ipv4.src_addr', ip_to_int(src_ip), ip_to_int('255.255.255.255')),
                                    ('hdr.ipv4.dst_addr', ip_to_int(dst_ip), ip_to_int('255.255.255.255'))],
                                data=[],
                                action_name='Ingress.drop')
            return 0

    def clear_tables(self):
        # self.bfrt.clear_tables()
        self.bfrt.clear_table('pipe.Ingress.tcp_flow')
        self.bfrt.clear_table('pipe.Ingress.udp_flow')
        self.bfrt.clear_table('pipe.Ingress.icmp_flow')
        return 0
    
if __name__ == "__main__":
    controller = Bfrt_GRPC_Server()
    # controller.tcp_flow_add_with_drop('10.0.0.1', '10.0.0.2', 10, 20)
    # controller.udp_flow_add_with_drop('10.0.0.3', '10.0.0.4', 30, 40)
    # controller.icmp_flow_add_with_drop('10.0.0.5', '10.0.0.6')
    controller.dump_table('pipe.Ingress.tcp_flow')
    controller.dump_table('pipe.Ingress.udp_flow')
    controller.dump_table('pipe.Ingress.icmp_flow')
    controller.clear_tables()
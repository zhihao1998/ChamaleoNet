
from bfrt_grpc_helper import BfRtAPI
import binascii
import socket

remote_grpc_addr = '192.168.24.69:50052'
local_grpc_addr = 'localhost:50052'

def ip_to_int(ip):
    return int(binascii.hexlify(socket.inet_aton(ip)),16)

def int_to_ip(ip_int):
    return socket.inet_ntoa(binascii.unhexlify(hex(ip_int)[2:]))

def mask_to_int(mask):
    return int(binascii.hexlify(socket.inet_aton(mask)),16)

class Bfrt_GRPC_Client:
    def __init__(self, grpc_addr=remote_grpc_addr):
        self.bfrt = BfRtAPI(client_id=1, grpc_addr=grpc_addr)
        self.installed_flow_key = set()   
     
    def init_key_annotation(self):
        table = self.bfrt.table_get('pipe.Ingress.active_host_tbl')
        table.info.key_field_annotation_add("hdr.meta.internal_ip", "ipv4")
    
    def print_tables_info(self):
        return self.bfrt.print_tables_info()

    def print_table_info(self, table_name):
        return self.bfrt.print_table_info(table_name)
    
    def dump_table(self, table_name):
        return self.bfrt.dump_table(table_name)
    
    def clear_table(self, table_name):
        return self.bfrt.clear_table(table_name)
    
    def get_table_usage(self, table_name) -> int:
        # return int(self.bfrt.get_table_usage(table_name))
        return len(self.installed_flow_key)

    def internal_host_add_with_drop(self, internal_ip, internal_port, ip_protocol):
        match_key = (internal_ip, internal_port, ip_protocol)
        try:
            if match_key in self.installed_flow_key:
                # print(f"Flow: {match_key} already installed")
                return 0
            
            # print(f"Adding flow: {match_key}, already installed flow number: {len(self.installed_flow_key)}")
            self.installed_flow_key.add(match_key)
            self.bfrt.entry_add(table_name='pipe.Ingress.active_host_tbl', 
                                keys=[('meta.internal_ip', ip_to_int(internal_ip)),
                                    ('meta.internal_port', internal_port),
                                    ('meta.ip_protocol', ip_protocol)],
                                data=[],
                                action_name='Ingress.drop')
        except Exception as e:
            print(e)                                                      
        return 1

    def clear_tables(self):
        self.bfrt.clear_table('pipe.Ingress.active_host_tbl')
        return 0
    
    def clean_all_idle_entries(self):
        # self.bfrt.clean_idle_entries('active_host_tbl')
        # return 0
        """
        Clean all idle entries in the table
        
        Args:
            table_name (str) : Name of the table
        """
        table = self.bfrt.bfrt_info.table_get('active_host_tbl')
        # Update all hit state before deleting
        table.operations_execute(self.bfrt.target, 'UpdateHitState')
        deleted_entries = 0

        for (data, key) in table.entry_get(self.bfrt.target):
            if data.to_dict()["$ENTRY_HIT_STATE"] == "ENTRY_IDLE":
                deleted_entries += 1
                # print("Deleting entry with key: {}".format(key))
                table.entry_del(self.bfrt.target, [key])
                
                ip = int_to_ip(key.to_dict()["meta.internal_ip"]['value'])
                port = key.to_dict()["meta.internal_port"]['value']
                protocol = key.to_dict()["meta.ip_protocol"]['value']

                self.installed_flow_key.remove((ip, port, protocol))
                # try:                
                #     self.installed_flow_key.remove((ip, port, protocol))
                # except Exception as e:
                #     print(f"Error removing flow: {ip, port, protocol}, {e}")

        print(f"Deleted {deleted_entries} idle entries!")
        return 0
    
    
    
if __name__ == "__main__":
    controller = Bfrt_GRPC_Client(grpc_addr=remote_grpc_addr)
    controller.clean_all_idle_entries()
    # controller.clear_tables()
    # controller.internal_host_add_with_drop('130.192.9.161', 1000, 6)
    # controller.dump_table('pipe.Ingress.active_host_tbl')
    # controller.print_table_info('active_host_tbl')

    # controller.udp_flow_add_with_drop('130.192.9.161', '8.8.8.8', 61434, 53)
    # controller.icmp_flow_add_with_drop('10.0.0.5', '10.0.0.6')
    # controller.dump_table('pipe.Ingress.tcp_flow')
    # controller.dump_table('pipe.Ingress.udp_flow')
    # controller.dump_table('pipe.Ingress.icmp_flow')
    # controller.clear_tables()
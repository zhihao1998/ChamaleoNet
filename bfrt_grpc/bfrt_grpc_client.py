
from bfrt_grpc_helper import BfRtAPI
import binascii
import socket
import bfrt_grpc.client as gc
import time


remote_grpc_addr = '192.168.24.69:50052'
local_grpc_addr = 'localhost:50052'

def ip_to_int(ip):
    return int(binascii.hexlify(socket.inet_aton(ip)),16)

def int_to_ip(ip_int):
    return socket.inet_ntoa(binascii.unhexlify(hex(ip_int)[2:]))

def mask_to_int(mask):
    return int(binascii.hexlify(socket.inet_aton(mask)),16)

def mac_to_bytes(mac_str):
    return bytes.fromhex(mac_str.replace(':', ''))

class Bfrt_GRPC_Client:
    def __init__(self, grpc_addr=remote_grpc_addr):
        print(f"Connecting to the P4Runtime server {grpc_addr}")
        self.bfrt = BfRtAPI(client_id=1, grpc_addr=grpc_addr)
        self.installed_flow_key = set()   
        self.service_table = self.bfrt.bfrt_info.table_get('active_host_tbl')
        self.target = gc.Target()

        print("Connected to the P4Runtime server")
     
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
    
    def get_table_usage(self) -> int:
        # return int(self.bfrt.get_table_usage(table_name))
        return len(self.installed_flow_key)

    def internal_host_add_with_drop(self, internal_ip, internal_port, ip_protocol):
        match_key = (internal_ip, internal_port, ip_protocol)
        try:
            # if match_key in self.installed_flow_key:
                # print(f"Flow: {match_key} already installed")
                # return 0
            
            # print(f"Adding flow: {match_key}, already installed flow number: {len(self.installed_flow_key)}")
            self.installed_flow_key.add(match_key)
            self.bfrt.entry_add(table_name='pipe.Ingress.active_host_tbl', 
                                keys=[('meta.internal_ip', internal_ip),
                                    ('meta.internal_port', internal_port),
                                    ('meta.ip_protocol', ip_protocol)],
                                data=[],
                                action_name='Ingress.drop')
        except Exception as e:
            print(e)                                                      
        return 1

    def clear_tables(self):
        # remove all entries
        # set default again
        try:
            self.service_table.entry_del(self.target, [])
        except Exception as e:
            print("Problem clearing table entries: ", e)
            pass

        # check table type
        table_type = self.service_table.info.type_get()
        if "MatchAction" in table_type:
            try:
                self.service_table.default_entry_reset(self.target)
            except:
                pass
    
    def clean_all_idle_entries(self):
        """
        Clean all idle entries in the table
        """
        start_time = time.time()
        # Update all hit state before deleting        
        self.service_table.operations_execute(self.bfrt.target, 'UpdateHitState')

        key_list = []
        for (data, key) in self.service_table.entry_get(self.bfrt.target):
            if data.to_dict()["$ENTRY_HIT_STATE"] == "ENTRY_IDLE":
                key_list.append(key)

                ip = key.to_dict()["meta.internal_ip"]['value']
                port = key.to_dict()["meta.internal_port"]['value']
                protocol = key.to_dict()["meta.ip_protocol"]['value']
                self.installed_flow_key.remove((ip, port, protocol))

        if len(key_list) > 0:
            self.service_table.entry_del(self.bfrt.target, key_list)

        print(f"Deleted {len(key_list)} idle entries, cost {round(time.time() - start_time, 2)}s!")
        return 0
        
            
    def add_batch_entries(self, entry_key_list):
        key_list = []
        data_list = []
        for index, key in enumerate(entry_key_list):
            if (key[0], key[1], key[2]) in self.installed_flow_key:
                continue
            key_list.append(self.service_table.make_key([gc.KeyTuple("meta.internal_ip", key[0]),
                                                        gc.KeyTuple("meta.internal_port", key[1]),
                                                        gc.KeyTuple("meta.ip_protocol", key[2])]))
            self.installed_flow_key.add((key[0], key[1], key[2]))
            data_list.append(self.service_table.make_data([gc.DataTuple('$ENTRY_HIT_STATE', str_val="ENTRY_ACTIVE")], 'Ingress.drop'))
            
        self.service_table.entry_add(self.bfrt.target, key_list, data_list)
        return 1
    
    
    
if __name__ == "__main__":
    import random

    controller = Bfrt_GRPC_Client(grpc_addr=remote_grpc_addr)

    controller.clear_tables()

    start_time = time.time()
    controller.clean_all_idle_entries()

    entry_size = 30000
    start_time = time.time()
    test_key_list = []

    for i in range(entry_size):
        test_key_list.append([783663000+i, 10129, 6])
    controller.add_batch_entries(test_key_list)

    controller.clean_all_idle_entries()

    # start_time = time.time()
    # controller.clear_tables()
    # print("clear --- %s seconds ---" % (time.time() - start_time))

    # start_time = time.time()
    # for i in range(entry_size):
    #     controller.internal_host_add_with_drop(test_key_list[i][0], test_key_list[i][1], test_key_list[i][2])
    # print("separate --- %s seconds ---" % (time.time() - start_time))

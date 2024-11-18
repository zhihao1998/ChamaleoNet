#!/usr/bin/python3
import binascii
import socket
import os
import sys
import time
import traceback
from tabulate import tabulate
import random
import struct

#
# This is optional if you use proper PYTHONPATH
#
SDE_INSTALL = os.environ['SDE_INSTALL']

PYTHON3_VER = '{}.{}'.format(
    sys.version_info.major,
    sys.version_info.minor)
SDE_PYTHON3 = os.path.join(SDE_INSTALL, 'lib', 'python' + PYTHON3_VER,
                           'site-packages')

sys.path.append(SDE_PYTHON3)
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino'))
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino', 'bfrt_grpc'))

import bfrt_grpc.client as gc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2

remote_grpc_addr = '192.168.24.69:50052'
local_grpc_addr = 'localhost:50052'



def ip_to_int(ipv4_address):
    return struct.unpack('!I', socket.inet_aton(ipv4_address))[0]

def int_to_ip(ip_int):
   return socket.inet_ntoa(struct.pack('!I', ip_int))

def mask_to_int(mask):
    return int(binascii.hexlify(socket.inet_aton(mask)),16)

def mac_to_bytes(mac_str):
    return bytes.fromhex(mac_str.replace(':', ''))

class Bfrt_GRPC_Client:
    def __init__(self, 
                 entry_ttl=5000, 
                 clean_batch_size=1000,
                 grpc_addr=remote_grpc_addr,
                 client_id=0,
                 p4_name=None,
                 perform_bind=True,
                 timeout=1,
                 num_tries=5,
                 perform_subscribe=True,
                 target=gc.Target(),
                 enable_log=None):

        if perform_bind and not perform_subscribe:
            raise RuntimeError(
                "perform_bind must be equal to perform_subscribe")
        self.bfrt_info = None
        self.target = target
        self.installed_flow_key = set()  
        
        self.interface = gc.ClientInterface(
            grpc_addr, 
            client_id=client_id, 
            device_id=0,
            notifications=gc.Notifications(enable_idletimeout=True, 
                                           enable_entry_active=False, 
                                           enable_port_status_change=False, 
                                           enable_learn=False),
            timeout=timeout,
            num_tries=num_tries,
            perform_subscribe=perform_subscribe)

        # If p4_name wasn't specified, then perform a bfrt_info_get and set p4_name
        # to it
        if not p4_name:
            self.bfrt_info = self.interface.bfrt_info_get()
            self.p4_name = self.bfrt_info.p4_name_get()

        # Set forwarding pipeline config (For the time being we are just
        # associating a client with a p4). Currently the grpc server supports
        # only one client to be in-charge of one p4.
        if perform_bind:
            self.interface.bind_pipeline_config(self.p4_name)
        
        # set tables
        self.service_table = self.bfrt_info.table_get('pipe.Ingress.active_host_tbl')
        self.service_table.info.key_field_annotation_add("meta.internal_ip", "ipv4")
        self.service_table.attribute_idle_time_set(self.target, 
                                                   True, 
                                                   bfruntime_pb2.IdleTable.IDLE_TABLE_NOTIFY_MODE,
                                                   1000)
        self.entry_ttl = entry_ttl
        self.clean_batch_size = clean_batch_size
        # self.small_batch_size = 500
        self.enable_log = enable_log
        self.set_log("bfrt_grpc_client.log")

    def set_log(self, log_file):
        self.enable_log = True
        self.log_file = open(log_file, "w+")
        self.log_file.write("time,op,num,cost\n")

    def __getattr__(self, name):
        """Adds methods from the :py:class:`bfrt_grpc.client.ClientInterface` class."""
        return getattr(self.interface, name)            

    def print_tables_info(self):
        # Print the list of tables in the "pipe" node
        dev_tgt = self.target

        data = []
        for name in self.bfrt_info.table_dict.keys():
            if name.split('.')[0] == 'pipe':
                # pdb.set_trace()
                t = self.bfrt_info.table_get(name)
                table_name = t.info.name_get()
                if table_name != name:
                    continue
                table_type = t.info.type_get()
                try:
                    result = t.usage_get(dev_tgt)
                    table_usage = next(result)
                except:
                    table_usage = 'n/a'
                table_size = t.info.size_get()
                data.append([table_name, table_type, table_usage, table_size])

        print(
            tabulate(
                data,
                headers=['Full Table Name', 'Type', 'Usage', 'Capacity']))

    def print_table_info(self, table_name):

        print("====Table Info===")
        t = self.bfrt_info.table_get(table_name)
        print("{:<30}: {}".format("TableName", t.info.name_get()))
        print("{:<30}: {}".format("Size", t.info.size_get()))
        try:
            print("{:<30}: {}".format("Usage", next(t.usage_get(self.target))))
        except:
            print("{:<30}: {}".format("Usage", 'n/a'))
        print("{:<30}: {}".format("Actions", t.info.action_name_list_get()))
        print("{:<30}:".format("KeyFields"))
        for field in sorted(t.info.key_field_name_list_get()):
            print("  {:<28}: {} => {}".format(
                field, t.info.key_field_type_get(field),
                t.info.key_field_match_type_get(field)))
        print("{:<30}:".format("DataFields"))
        for field in t.info.data_field_name_list_get():
            print("  {:<28}: {} {}".format(
                "{} ({})".format(field, t.info.data_field_id_get(field)),
                t.info.data_field_type_get(field),
                t.info.data_field_size_get(field),
            ))
        print("================")

    def clear_table(self, table_name):
        """clear a table"""
        t = self.bfrt_info.table_get(table_name)
        # remove all entries
        # set default again
        try:
            t.entry_del(self.target, [])
        except:
            print("Problem clearing {}".format(table_name))
            pass

        # check table type
        table_type = t.info.type_get()
        if "MatchAction" in table_type:
            try:
                t.default_entry_reset(self.target)
            except:
                pass


    # Interaction with C controller
    def get_local_flow_entry_num(self) -> int:
        return len(self.installed_flow_key)
    
    def get_table_usage(self) -> int:
        usage = int(next(self.service_table.usage_get(self.target, flags={"from_hw":False})))
        return usage

    def clear_service_table(self):
        """clear service table"""
        try:
            self.service_table.entry_del(self.target, [])
        except:
            print("Problem clearing active service table")
    

    # def idle_entry_single_clean(self):
    #     """
    #     Clean all idle entries in the table with notification mode
    #     """
    #     count = 0
    #     start_time = time.time()
    #     while count < self.clean_batch_size:
    #         try:
    #             idle_notification = self.interface.idletime_notification_get(timeout=0.2)
    #             recv_key = self.bfrt_info.key_from_idletime_notification(idle_notification)
    #             key_dict = recv_key.to_dict()
    #             ip = key_dict["meta.internal_ip"]['value']
    #             port = key_dict["meta.internal_port"]['value']
    #             protocol = key_dict["meta.ip_protocol"]['value']
    #             # log_file.write(f"{start_time}, Delete entry: {ip_to_int(ip)}, {port}, {protocol}\n")
    #             self.installed_flow_key.remove((ip_to_int(ip), port, protocol))

    #             self.service_table.entry_del(self.target, [recv_key])
    #             count += 1
    #         except RuntimeError as e:
    #             # traceback.print_exc()
    #             print(e)
    #             break
    #         except KeyError as e:
    #             # log_file.write(f"{start_time}, Error: {e}\n")
    #             # print(f"Trying to delete a non-exist entry, {e}")
    #             pass
    #     log_file.write(f"{start_time},remove,{count},{round(time.time() - start_time, 5)}\n")
    #     log_file.flush()
    #     return 0
    
    # def entry_single_add(self, entry_key_list):

    #     start_time = time.time()
    #     for index, key in enumerate(entry_key_list):
    #         if (key[0], key[1], key[2]) in self.installed_flow_key:
    #             continue
    #         key_list = self.service_table.make_key([gc.KeyTuple("meta.internal_ip", key[0]),
    #                                                     gc.KeyTuple("meta.internal_port", key[1]),
    #                                                     gc.KeyTuple("meta.ip_protocol", key[2])])
    #         self.installed_flow_key.add((key[0], key[1], key[2]))
    #         # log_file.write(f"{start_time}, Add entry: {key}\n")
    #         # for poll mode
    #         # data_list.append(self.service_table.make_data([gc.DataTuple('$ENTRY_HIT_STATE', str_val="ENTRY_ACTIVE")], 'Ingress.drop'))

    #         # for notification mode
    #         data_list = self.service_table.make_data([gc.DataTuple('$ENTRY_TTL', self.entry_ttl)], 
    #                                                  'Ingress.drop')
    #         self.service_table.entry_add(self.target, [key_list], [data_list])

    #     log_file.write(f"{time.time()},add,{len(entry_key_list)},{round(time.time() - start_time, 5)}\n")
    #     log_file.flush()
    #     return 1
    
    # # small batch clean
    # def idle_entry_batch_clean(self):
    #     """
    #     Clean all idle entries in the table with notification mode
    #     """
    #     start_time = time.time()
    #     count = 0
    #     key_list = []
    #     while count < self.clean_batch_size:
    #         try:
    #             idle_notification = self.interface.idletime_notification_get(timeout=0.2)
    #             recv_key = self.bfrt_info.key_from_idletime_notification(idle_notification)
    #             key_dict = recv_key.to_dict()
    #             ip = key_dict["meta.internal_ip"]['value']
    #             port = key_dict["meta.internal_port"]['value']
    #             protocol = key_dict["meta.ip_protocol"]['value']
    #             # log_file.write(f"{start_time}, Delete entry: {[ip_to_int(ip), port, protocol]}\n")
    #             self.installed_flow_key.remove((ip_to_int(ip), port, protocol))

    #             key_list.append(recv_key)
    #             count += 1
    #         except RuntimeError as e:
    #             # traceback.print_exc()
    #             print(e)
    #             break
    #         except KeyError as e:
    #             # log_file.write(f"{start_time}, Error: {e}\n")
    #             # print(f"Trying to delete a non-exist entry, {e}")
    #             pass

    #         if len(key_list) >= self.small_batch_size:
    #             self.service_table.entry_del(self.target, key_list)
    #             key_list = []
        
    #     if len(key_list) > 0:
    #         self.service_table.entry_del(self.target, key_list)

    #     log_file.write(f"{start_time},remove,{count},{round(time.time() - start_time, 5)}\n")
    #     log_file.flush()
    #     return 0
        
            
    # def entry_batch_add(self, entry_key_list):
    #     key_list = []
    #     data_list = []
    #     count = 0
    #     start_time = time.time()
    #     for index, key in enumerate(entry_key_list):
    #         if (key[0], key[1], key[2]) in self.installed_flow_key:
    #             continue
    #         key_list.append(self.service_table.make_key([gc.KeyTuple("meta.internal_ip", key[0]),
    #                                                     gc.KeyTuple("meta.internal_port", key[1]),
    #                                                     gc.KeyTuple("meta.ip_protocol", key[2])]))
    #         self.installed_flow_key.add((key[0], key[1], key[2]))
    #         # log_file.write(f"{start_time}, Add entry: {key}\n")
    #         # for poll mode
    #         # data_list.append(self.service_table.make_data([gc.DataTuple('$ENTRY_HIT_STATE', str_val="ENTRY_ACTIVE")], 'Ingress.drop'))

    #         # for notification mode
    #         data_list.append(self.service_table.make_data([gc.DataTuple('$ENTRY_TTL', self.entry_ttl)], 
    #                                                       'Ingress.drop'))
    #         if len(key_list) >= self.small_batch_size:
    #             self.service_table.entry_add(self.target, key_list, data_list)
    #             count += len(key_list)
    #             key_list = []
    #             data_list = []

    #     if len(key_list) >= 0:
    #         self.service_table.entry_add(self.target, key_list, data_list)
    #         count += len(key_list)
    #         key_list = []
    #         data_list = []
    #     # print(f"Added {len(key_list)} entries, cost {round(time.time() - start_time, 2)}s!")
    #     log_file.write(f"{time.time()},add,{count},{round(time.time() - start_time, 5)}\n")
    #     log_file.flush()
    #     return 1
    
    def idle_entry_batch_clean(self):
        """
        Clean all idle entries in the table with notification mode
        """
        start_time = time.time()
        key_list = []
        count = 0
        while len(key_list) < self.clean_batch_size:
            try:
                idle_notification = self.interface.idletime_notification_get(timeout=0.2)
                recv_key = self.bfrt_info.key_from_idletime_notification(idle_notification)
                key_dict = recv_key.to_dict()
                ip = key_dict["meta.internal_ip"]['value']
                port = key_dict["meta.internal_port"]['value']
                protocol = key_dict["meta.ip_protocol"]['value']
                # log_file.write(f"{start_time}, Delete entry: {[ip_to_int(ip), port, protocol]}\n")
                self.installed_flow_key.remove((ip_to_int(ip), port, protocol))

                key_list.append(recv_key)
                count += 1
            except RuntimeError as e:
                # traceback.print_exc()
                print(e)
                break
            except KeyError as e:
                # log_file.write(f"{start_time}, Error: {e}\n")
                # print(f"Trying to delete a non-exist entry, {e}")
                pass
            
        if len(key_list) > 0:
            self.service_table.entry_del(self.target, key_list)
            if self.enable_log:
                self.log_file.write(f"{start_time},remove,{count},{round(time.time() - start_time, 5)}\n")
                self.log_file.flush()
        return 0
        
            
    def entry_batch_add(self, entry_key_list):
        key_list = []
        data_list = []
        start_time = time.time()
        for index, key in enumerate(entry_key_list):
            if (key[0], key[1], key[2]) in self.installed_flow_key:
                continue
            key_list.append(self.service_table.make_key([gc.KeyTuple("meta.internal_ip", key[0]),
                                                        gc.KeyTuple("meta.internal_port", key[1]),
                                                        gc.KeyTuple("meta.ip_protocol", key[2])]))
            self.installed_flow_key.add((key[0], key[1], key[2]))
            # log_file.write(f"{start_time}, Add entry: {key}\n")
            # for poll mode
            # data_list.append(self.service_table.make_data([gc.DataTuple('$ENTRY_HIT_STATE', str_val="ENTRY_ACTIVE")], 'Ingress.drop'))

            # for notification mode
            data_list.append(self.service_table.make_data([gc.DataTuple('$ENTRY_TTL', self.entry_ttl)], 
                                                          'Ingress.drop'))
        self.service_table.entry_add(self.target, key_list, data_list)
        # print(f"Added {len(key_list)} entries, cost {round(time.time() - start_time, 2)}s!")
        if self.enable_log:
            self.log_file.write(f"{time.time()},add,{len(key_list)},{round(time.time() - start_time, 5)}\n")
            self.log_file.flush()
        return 1
    
    def entry_batch_remove(self, entry_key_list):
        key_list = []
        start_time = time.time()
        for index, key in enumerate(entry_key_list):
            if (key[0], key[1], key[2]) in self.installed_flow_key:
                continue
            key_list.append(self.service_table.make_key([gc.KeyTuple("meta.internal_ip", key[0]),
                                                        gc.KeyTuple("meta.internal_port", key[1]),
                                                        gc.KeyTuple("meta.ip_protocol", key[2])]))
            self.installed_flow_key.add((key[0], key[1], key[2]))

        self.service_table.entry_del(self.target, key_list)
        # print(f"Added {len(key_list)} entries, cost {round(time.time() - start_time, 2)}s!")
        if self.enable_log:
            self.log_file.write(f"{time.time()},add,{len(key_list)},{round(time.time() - start_time, 5)}\n")
            self.log_file.flush()
        return 1
    
    
    
if __name__ == "__main__":

    controller = Bfrt_GRPC_Client()

    controller.clear_service_table()
    entry_size = 300
    
    test_key_list = []
    for i in range(entry_size):
        test_key_list.append([783663000+i, 10129, 6])
    start_time = time.time()
    controller.entry_batch_add(test_key_list)
    print("add --- %s seconds ---" % (time.time() - start_time))
    print(controller.get_table_usage())
    time.sleep(6)

    # single clean time
    start_time = time.time()
    controller.idle_entry_single_clean()
    print("single clean --- %s seconds ---" % (time.time() - start_time))
    time.sleep(6)

    controller.entry_batch_add(test_key_list)
    time.sleep(6)
    print("add entries again, table usage: ", controller.get_table_usage())

    # batch clean time
    start_time = time.time()
    controller.idle_entry_batch_clean()
    print("batch clean --- %s seconds ---" % (time.time() - start_time))

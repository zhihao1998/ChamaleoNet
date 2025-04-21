#!/usr/bin/python3
import binascii
import ipaddress
import socket
import os
import sys
import time
import pickle
from collections import Counter
from tabulate import tabulate
import struct
from datetime import datetime

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
                 enable_time_log=False,
                 enable_rule_log=False):

        if perform_bind and not perform_subscribe:
            raise RuntimeError(
                "perform_bind must be equal to perform_subscribe")
        
        self.bfrt_info = None
        self.target = target
        self.installed_flows = set()
        self.installed_flows_counter = Counter()

        self.active_hosts = [0] * 65536
        self.base_ip_int = int(ipaddress.IPv4Network("154.200.0.0/16").network_address)
        self.active_hosts_file = "/home/zhihaow/codes/honeypot_c_controller/log/active_hosts/active_hosts.log"
        
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

        # initialize log files
        self.enable_time_log = enable_time_log
        self.enable_rule_log = enable_rule_log
        self.init_log()

    def init_log(self):
        now = datetime.now()
        cur_date = now.strftime("%Y%m%d")
        cur_hour = now.hour
        cur_min = now.minute
        cur_sec = now.second
        cur_time = ''.join([cur_date, '_', str(cur_hour), '-', str(cur_min), '-', str(cur_sec)])

        # self.log_file = open(f"/home/zhihaow/codes/honeypot_c_controller/log/{cur_time}_bfrt.log", "w+")

        if self.enable_time_log:
            self.time_log_file_fp = open(f"/home/zhihaow/codes/honeypot_c_controller/log/{cur_time}_bfrt_time.log", "w+")
            self.time_log_file_fp.write("time,op,num,cost\n")

        if self.enable_rule_log:
            self.last_rule_log_time = time.time()
            

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
        return len(self.installed_flows)
    
    def get_table_usage(self) -> int:
        usage = int(next(self.service_table.usage_get(self.target, flags={"from_hw":False})))
        return usage

    def clear_service_table(self):
        """clear service table"""
        try:
            self.service_table.entry_del(self.target, [])
        except:
            print("Problem clearing active service table")
    

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
                # self.installed_flows[f'{ip}_{port}_{protocol}'][0] = 0
                self.installed_flows.remove(f'{ip_to_int(ip)}_{port}_{protocol}')

                key_list.append(recv_key)
                count += 1
            except RuntimeError as e:
                # traceback.print_exc()
                # self.log_file.write(f"{start_time}, Remove Error: {e}\n")
                break
            except KeyError as e:
                # log_file.write(f"{start_time}, Error: {e}\n")
                # print(f"Trying to delete a non-exist entry, {e}")
                # self.log_file.write(f"{start_time}, Remove Error: {e}\n")
                pass
            
        if len(key_list) > 0:
            # print(f"clean {len(key_list)} entries")
            self.service_table.entry_del(self.target, key_list)

            if self.enable_time_log:
                self.time_log_file_fp.write(f"{time.time()},remove,{count},{round(time.time() - start_time, 5)}\n")
                self.time_log_file_fp.flush()
        return 0
        
            
    def entry_batch_add(self, entry_key_list):
        key_list = []
        data_list = []
        start_time = time.time()
        try:
            for index, key in enumerate(entry_key_list):
                if self.enable_rule_log:
                    self.installed_flows_counter[f'{int_to_ip(key[0])}_{key[1]}_{key[2]}'] += 1

                if f'{key[0]}_{key[1]}_{key[2]}' in self.installed_flows:
                    continue
                key_list.append(self.service_table.make_key([gc.KeyTuple("meta.internal_ip", key[0]),
                                                            gc.KeyTuple("meta.internal_port", key[1]),
                                                            gc.KeyTuple("meta.ip_protocol", key[2])]))
                self.installed_flows.add(f'{key[0]}_{key[1]}_{key[2]}')
                # for poll mode
                # data_list.append(self.service_table.make_data([gc.DataTuple('$ENTRY_HIT_STATE', str_val="ENTRY_ACTIVE")], 'Ingress.drop'))

                # for notification mode
                data_list.append(self.service_table.make_data([gc.DataTuple('$ENTRY_TTL', self.entry_ttl)], 
                                                            'Ingress.drop'))
            self.service_table.entry_add(self.target, key_list, data_list)

            if self.enable_time_log:
                self.time_log_file_fp.write(f"{time.time()},add,{len(key_list)},{round(time.time() - start_time, 5)}\n")
                self.time_log_file_fp.flush()
            
            if self.enable_rule_log:
                c_time = time.time()
                if c_time - self.last_rule_log_time > 1800:
                    self.write_counter_to_file()
                    self.last_rule_log_time = c_time
                    
        except Exception as e:
            pass
            # self.log_file.write(f"{start_time}, Add Error: {e}\n")
            # traceback.print_exc()
        return 1
    
    def write_counter_to_file(self):
        now = datetime.now()
        cur_date = now.strftime("%Y%m%d")
        cur_hour = now.hour
        cur_min = now.minute
        cur_sec = now.second
        cur_time = ''.join([cur_date, '_', str(cur_hour), '-', str(cur_min), '-', str(cur_sec)])
        rule_log_file = f"/home/zhihaow/codes/honeypot_c_controller/log/rule_counter/{cur_time}_bfrt_rule.pkl"

        with open(rule_log_file, "wb") as f:
            pickle.dump(self.installed_flows_counter, f)

        self.installed_flows_counter = Counter()

    def get_active_hosts(self):
        """
        Get all active hosts in the table from the local flows
        """
        self.active_hosts = [0] * 65536
        for entry in self.installed_flows:
            ip, port, protocol = entry.split('_')
            ip = int(ip)
            offset = ip - self.base_ip_int
            if 0 <= offset < 65536:
                self.active_hosts[offset] = 1
                
        # timestamp = int(time.time())
        # bitmap_str = ''.join(str(x) for x in self.active_hosts)

        # with open(self.active_hosts_file, "a") as f: 
        #     f.write(f"{timestamp},{bitmap_str}\n")
        #     f.flush()
        return self.active_hosts
 
    
    
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

    # # single clean time
    # start_time = time.time()
    # controller.idle_entry_single_clean()
    # print("single clean --- %s seconds ---" % (time.time() - start_time))
    # time.sleep(6)

    controller.entry_batch_add(test_key_list)
    time.sleep(6)
    print("add entries again, table usage: ", controller.get_table_usage())

    # batch clean time
    start_time = time.time()
    controller.idle_entry_batch_clean()
    print("batch clean --- %s seconds ---" % (time.time() - start_time))

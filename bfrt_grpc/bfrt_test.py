#!/usr/bin/python3
import binascii
import ipaddress
import os
import socket
import struct
import sys
from collections import Counter

#
# This is optional if you use proper PYTHONPATH
#
SDE_INSTALL = os.environ["SDE_INSTALL"]

PYTHON3_VER = "{}.{}".format(sys.version_info.major, sys.version_info.minor)
SDE_PYTHON3 = os.path.join(SDE_INSTALL, "lib", "python" + PYTHON3_VER, "site-packages")

sys.path.append(SDE_PYTHON3)
sys.path.append(os.path.join(SDE_PYTHON3, "tofino"))
sys.path.append(os.path.join(SDE_PYTHON3, "tofino", "bfrt_grpc"))

import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc

remote_grpc_addr = "192.168.24.69:50052"  # Change this to your controller's IP address
local_grpc_addr = "localhost:50052"
base_ip_range = "154.200.0.0/16"  # Change this to your IP range to be monitored


def ip_to_int(ipv4_address):
    return struct.unpack("!I", socket.inet_aton(ipv4_address))[0]


def int_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack("!I", ip_int))


def mask_to_int(mask):
    return int(binascii.hexlify(socket.inet_aton(mask)), 16)


def mac_to_bytes(mac_str):
    return bytes.fromhex(mac_str.replace(":", ""))


class Bfrt_GRPC_Client:
    def __init__(
        self,
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
    ):
        if perform_bind and not perform_subscribe:
            raise RuntimeError("perform_bind must be equal to perform_subscribe")

        self.bfrt_info = None
        self.target = target
        self.installed_flows = set()
        self.installed_flows_counter = Counter()

        self.active_hosts = [0] * 65536
        self.base_ip_int = int(ipaddress.IPv4Network(base_ip_range).network_address)

        self.interface = gc.ClientInterface(
            grpc_addr,
            client_id=client_id,
            device_id=0,
            notifications=gc.Notifications(
                enable_idletimeout=True, enable_entry_active=False, enable_port_status_change=False, enable_learn=False
            ),
            timeout=timeout,
            num_tries=num_tries,
            perform_subscribe=perform_subscribe,
        )

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
        self.service_table = self.bfrt_info.table_get("pipe.Ingress.active_host_tbl")
        self.service_table.info.key_field_annotation_add("meta.internal_ip", "ipv4")
        self.service_table.attribute_idle_time_set(
            self.target, True, bfruntime_pb2.IdleTable.IDLE_TABLE_NOTIFY_MODE, 1000
        )
        self.entry_ttl = entry_ttl
        self.clean_batch_size = clean_batch_size
        self.max_flows = 0

    def __getattr__(self, name):
        """Adds methods from the :py:class:`bfrt_grpc.client.ClientInterface` class."""
        return getattr(self.interface, name)

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

    def get_key_value(self, key):
        return key.to_dict()["$REGISTER_INDEX"]["value"]

    def get_data_value(self, data):
        return data.to_dict()["%s.f1" % self.name]

    def dump_register(self, register_name):
        reg = self.bfrt_info.table_get(register_name)
        self.name = register_name
        reg_values = []
        for data, key in reg.entry_get(self.target, []):
            reg_values.append(self.get_data_value(data))
        print(reg_values)


if __name__ == "__main__":
    controller = Bfrt_GRPC_Client()
    # controller.clear_table("Ingress.bloom_group0_epoch0")
    # controller.clear_table("Ingress.bloom_group1_epoch0")
    # controller.clear_table("pipe.Ingress.bloom_group0_epoch1")
    # controller.clear_table("pipe.Ingress.bloom_group1_epoch1")
    print("dump register: bloom_group0_epoch0")
    controller.dump_register("Ingress.bloom_group0_epoch0")
    print("dump register: bloom_group1_epoch0")
    controller.dump_register("Ingress.bloom_group1_epoch0")

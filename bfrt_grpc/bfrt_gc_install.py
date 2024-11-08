
# This file is used to install the table entries 

#!/usr/bin/python3

import os
import sys
import time

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

remote_grpc_addr = '192.168.24.69:50052'
local_grpc_addr = 'localhost:50052'

class BfRtAPI:
    """Sets up connection to gRPC server and bind.

    Args:
        grpc_addr (str)                               : gRPC address and port to connect to
        client_id (int)                               : Client ID
        p4_name (str)                                 : Name of P4 program. If none is given,
                                                        then the test performs a bfrt_info_get() and binds to the first
                                                        P4 that comes as part of the bfrt_info_get()
        notifications (bfrt_grpc.client.Notifications): A Notifications object.
        perform_bind (bool)                           : Set this to **False** if binding is not required
        timeout (int or float)                        : Timeout to wait for connection
        num_tries (int)                               : Number of connection tries
        perform_subscribe (bool)                      : Set this to **False** if client does not need to
                                                        subscribe for any notifications
        target (bfrt_grpc.client.Target)              : Target to use for the APIs

    Returns:
        tuple: ``(interface, bfrt_info)`` where ``interface`` is the client interface
        and ``bfrt_info`` is a :py:class:`~bfrt_grpc.client._BfRtInfo` containing all
        the information of the P4 program installed in the switch.

    Note:
        If you need to disable any notifications, then do the below as example::

            Notifications(enable_learn=False)

        Otherwise default value is sent as below::

            enable_learn = True
            enable_idletimeout = True
            enable_port_status_change = True
    """

    def __init__(self, grpc_addr=remote_grpc_addr,
                 client_id=1,
                 p4_name=None,
                 notifications=None,
                 perform_bind=None,
                 timeout=1,
                 num_tries=5,
                 perform_subscribe=False):

        if perform_bind and not perform_subscribe:
            raise RuntimeError(
                "perform_bind must be equal to perform_subscribe")

        self.bfrt_info = None
        self.target = None
        self.entry_ttl = 5000

        self.interface = gc.ClientInterface(
            grpc_addr, client_id=client_id, device_id=0, 
            timeout=timeout, num_tries=num_tries)

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

        # Set default target
        self.target = gc.Target(device_id=0)

        # set tables
        self.service_table = self.bfrt_info.table_get('pipe.Ingress.active_host_tbl')
        self.service_table.info.key_field_annotation_add("meta.internal_ip", "ipv4")

    def service_table_add_with_drop(self, entry_key_list):
        success = False
        while not success:
            key_list = []
            data_list = []
            for index, key in enumerate(entry_key_list):
                key_list.append(self.service_table.make_key([gc.KeyTuple("meta.internal_ip", key[0]),
                                                            gc.KeyTuple("meta.internal_port", key[1]),
                                                            gc.KeyTuple("meta.ip_protocol", key[2])]))
                # for notification mode
                data_list.append(self.service_table.make_data([gc.DataTuple('$ENTRY_TTL', self.entry_ttl)], 'Ingress.drop'))
                print("Adding entry: ", key)   
            try: 
                self.service_table.entry_add(self.target, key_list, data_list, p4_name='tf_honeypot')
                success = True
            except Exception as e:
                print("Exception: ", e)
    
    def service_table_clear(self):
        self.service_table.entry_del(self.target, [], p4_name='tf_honeypot')
        

if __name__ == '__main__':
    api = BfRtAPI()
    api.service_table_clear()
    for t in range(1, 100):
        key_list = [(f'130.192.{t}.{i}', 1, 1) for i in range(100)]
        api.service_table_add_with_drop(key_list)
        time.sleep(0.5)
        


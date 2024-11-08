
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
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2

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
                 client_id=0,
                 p4_name=None,
                 perform_bind=True,
                 timeout=1,
                 num_tries=5,
                 perform_subscribe=True,
                 target=gc.Target()):

        if perform_bind and not perform_subscribe:
            raise RuntimeError(
                "perform_bind must be equal to perform_subscribe")

        self.bfrt_info = None
        notifications = gc.Notifications(enable_idletimeout=True, 
                                         enable_entry_active=False, 
                                         enable_port_status_change=False, 
                                         enable_learn=False)

        self.interface = gc.ClientInterface(
            grpc_addr, client_id=client_id, device_id=0,
            notifications=notifications, timeout=timeout, num_tries=num_tries,
            perform_subscribe=perform_subscribe)

        # If p4_name wasn't specified, then perform a bfrt_info_get and set p4_name to it
        if not p4_name:
            self.bfrt_info = self.interface.bfrt_info_get()
            self.p4_name = self.bfrt_info.p4_name_get()

        # Set forwarding pipeline config (For the time being we are just
        # associating a client with a p4). Currently the grpc server supports
        # only one client to be in-charge of one p4.
        if perform_bind:
            self.interface.bind_pipeline_config(self.p4_name)

        # Set default target
        self.set_target(target)

        # set tables
        self.service_table = self.bfrt_info.table_get('pipe.Ingress.active_host_tbl')
        self.service_table.attribute_idle_time_set(self.target, 
                                                   True, 
                                                   bfruntime_pb2.IdleTable.IDLE_TABLE_NOTIFY_MODE,
                                                   1000)

    def __getattr__(self, name):
        """Adds methods from the :py:class:`bfrt_grpc.client.ClientInterface` class."""
        return getattr(self.interface, name)

    def set_target(self, target=gc.Target()):
        """Sets Target for the APIs.

        Args:
            target (bfrt_grpc.client.Target): Target to use for the APIs
        """
        self.target = target

    def clean_idle_entry(self):
        idle_notification = self.interface.idletime_notification_get(timeout=0.2)
        recv_key = self.bfrt_info.key_from_idletime_notification(idle_notification)
        success = False
        while not success:
            try:
                if recv_key:
                    self.service_table.entry_del(self.target, [recv_key])
                    print(f"Removed idle entry: {recv_key}")
                    success = True
            except Exception as e:
                print(e)
        
if __name__ == '__main__':
    bfrt = BfRtAPI()
    while True:
        try:
            bfrt.clean_idle_entry()
        except Exception as e:
            print(e)
            time.sleep(1)
        
        
        
#!/usr/bin/python3

import os
import sys
import time

from utils import import_bfrt_grpc
from portutils import PortInfo, config

# Attempt to import the gRPC BFRT 
# (see utils..import_bfrt_grpc for a list of paths to be set)
try:
    # try normal import
    import bfrt_grpc.client as gc
    print("Successfully imported client from bfrt_grpc")
except ModuleNotFoundError as e:
    try:
        # try setting python path for imports if not found
        gc = import_bfrt_grpc()
    except ModuleNotFoundError:
        print("Error importing client from bfrt_grpc")
        sys.exit(1)  # Exit script if import fails

# Initialize the GRPC client interface
for bfrt_client_id in range(10):
    try:
        client = gc.ClientInterface(
            grpc_addr = '127.0.0.1:50052',
            client_id = bfrt_client_id,
            device_id = 0,
            num_tries = 1)

        print('Connected to BF Runtime Server as client', bfrt_client_id)
    
        break   # exit loop if connection is successful

    except:
        print('Could not connect to BF Runtime server')
        quit

try:

    # Get information about the running program
    bfrt_info = client.bfrt_info_get()
    print('The target runs the program', bfrt_info.p4_name_get())

    # this is necesary step !!!!
    client.bind_pipeline_config(bfrt_info.p4_name_get())
    
except Exception as e:
    print("Error initializing GRPC client interface:", e)
    sys.exit(1)  # Exit script if initialization fails


# Setup switch ports.
#  config.interfaces contains the port names as dict keys
# PortInfo class is a wrapper to get the port configuration 
# in the format expected by BFRT tables
def setup_ports():
    ports = []
    for p,_ in config["interfaces"].items():
        ports.append(PortInfo(p))

    target = gc.Target(device_id=0, pipe_id=0xffff)
    port_table = bfrt_info.table_get("$PORT")

    table_keys = []
    table_data = []
    for pi in ports:
        
        print("Adding devport", pi.getDevPort(), "speed", pi.getSpeed(), "fec", pi.getFec())
        tk = port_table.make_key([gc.KeyTuple('$DEV_PORT', pi.getDevPort())])
        td = port_table.make_data([gc.DataTuple('$SPEED', str_val=pi.getSpeed()),
                                    gc.DataTuple('$FEC', str_val=pi.getFec()),
                                    gc.DataTuple('$PORT_ENABLE', bool_val=True)])
        table_keys.append(tk)
        table_data.append(td)

    port_table.entry_add(target, table_keys, table_data)



# README
# == what follows is taken from p4 examples in the SDE and can be used to see how read/write
#    the port tables. Similar examples are there to add/remove table entries in generic P4 program. 

#    Other useful examples are in the switchML GitHub repository.
#  ==




# def PortCfgTest(self, port1, port2):
#     logger.info("Test Port cfg table add read and delete operations")
#     target = client.Target(device_id=0, pipe_id=0xffff)

#     logger.info("PortCfgTest: Adding entry for port %d", port1.getDevPort())
#     self.port_table.entry_add(
#         target,
#         [self.port_table.make_key([client.KeyTuple('$DEV_PORT', port1.getDevPort())])],
#         [self.port_table.make_data([client.DataTuple('$SPEED', str_val=port1.getSpeed()),
#                                     client.DataTuple('$FEC', str_val=port1.getFec())])])

#     logger.info("PortCfgTest: Adding entry for port %d", port2.getDevPort())
#     n_lanes = speed_to_num_lanes(port2.getSpeed())

#     self.port_table.entry_add(
#         target,
#         [self.port_table.make_key([client.KeyTuple('$DEV_PORT', port2.getDevPort())])],
#         [self.port_table.make_data([client.DataTuple('$SPEED', str_val=port2.getSpeed()),
#                                     client.DataTuple('$FEC', str_val=port2.getFec()),
#                                     client.DataTuple('$N_LANES', n_lanes)])])

#     logger.info("PortCfgTest: Modifying entry for port %d", port1.getDevPort())
#     self.port_table.entry_mod(
#         target,
#         [self.port_table.make_key([client.KeyTuple('$DEV_PORT', port1.getDevPort())])],
#         [self.port_table.make_data([client.DataTuple('$PORT_ENABLE', bool_val=True),
#          client.DataTuple('$AUTO_NEGOTIATION', str_val="PM_AN_FORCE_ENABLE"),
#          client.DataTuple('$TX_MTU', 1500),
#          client.DataTuple('$RX_MTU', 1500),
#          client.DataTuple('$TX_PFC_EN_MAP', 1),
#          client.DataTuple('$RX_PFC_EN_MAP', 1),
#          client.DataTuple('$RX_PRSR_PRI_THRESH', 1),
#          client.DataTuple('$TX_PAUSE_FRAME_EN', bool_val=False),
#          client.DataTuple('$RX_PAUSE_FRAME_EN', bool_val=False),
#          client.DataTuple('$CUT_THROUGH_EN', bool_val=False),
#          client.DataTuple('$PORT_DIR', str_val="PM_PORT_DIR_DEFAULT")])])

#     logger.info("PortCfgTest: Modifying entry for port %d", port2.getDevPort())
#     if g_is_tofino3:
#         loop_str_val="BF_LPBK_PCS_NEAR"
#     else:
#         loop_str_val="BF_LPBK_MAC_NEAR"

#     self.port_table.entry_mod(
#         target,
#         [self.port_table.make_key([client.KeyTuple('$DEV_PORT', port2.getDevPort())])],
#         [self.port_table.make_data([client.DataTuple('$PORT_ENABLE', bool_val=True),
#                                     client.DataTuple('$RX_PRSR_PRI_THRESH', 2),
#                                     client.DataTuple('$LOOPBACK_MODE', str_val=loop_str_val)])])

#     logger.info("PortCfgTest: Reading entry for port %d", port1.getDevPort())
#     resp = self.port_table.entry_get(
#         target,
#         [self.port_table.make_key([client.KeyTuple('$DEV_PORT', port1.getDevPort())])])

#     logger.info("PortCfgTest: Validating entry read for port %d", port1.getDevPort())
#     for data, key in resp:
#         data = data.to_dict()
#         key = key.to_dict()
#         assert(key['$DEV_PORT']['value'] == port1.getDevPort())
#         assert(data['$SPEED'] == port1.getSpeed())
#         assert(data['$FEC'] == port1.getFec())
#         assert(data['$PORT_ENABLE'] == True)
#         assert(data['$AUTO_NEGOTIATION'] == 'PM_AN_FORCE_ENABLE')
#         assert(data['$TX_MTU'] == 1500)
#         assert(data['$RX_MTU'] == 1500)
#         assert(data['$TX_PFC_EN_MAP'] == 1)
#         assert(data['$RX_PFC_EN_MAP'] == 1)
#         assert(data['$TX_PAUSE_FRAME_EN'] == False)
#         assert(data['$RX_PAUSE_FRAME_EN'] == False)
#         assert(data['$CUT_THROUGH_EN'] == False)
#         assert(data['$RX_PRSR_PRI_THRESH'] == 1)
#         assert(data['$PORT_DIR'] == 'PM_PORT_DIR_DEFAULT')

#     logger.info("PortCfgTest: Reading entry for port %d", port2.getDevPort())
#     resp = self.port_table.entry_get(
#         target,
#         [self.port_table.make_key([client.KeyTuple('$DEV_PORT', port2.getDevPort())])])

#     logger.info("PortCfgTest: Validating entry read for port %d", port2.getDevPort())
#     for data, key in resp:
#         data = data.to_dict()
#         key = key.to_dict()
#         assert(key['$DEV_PORT']['value'] == port2.getDevPort())
#         assert(data['$SPEED'] == port2.getSpeed())
#         assert(data['$FEC'] == port2.getFec())
#         assert(data['$N_LANES'] == n_lanes)
#         assert(data['$PORT_ENABLE'] == True)
#         assert(data['$RX_PRSR_PRI_THRESH'] == 2)
#         assert(data['$LOOPBACK_MODE'] == loop_str_val)

#     logger.info("PortCfgTest: Wild card read")
#     resp = self.port_table.entry_get(target, None)

#     logger.info("PortCfgTest: Validating wild card read")
#     for data, key in resp:
#         data = data.to_dict()
#         key = key.to_dict()
#         port = key['$DEV_PORT']['value']
#         if port == port1.getDevPort():
#             assert(key['$DEV_PORT']['value'] == port1.getDevPort())
#             assert(data['$SPEED'] == port1.getSpeed())
#             assert(data['$FEC'] == port1.getFec())
#             assert(data['$PORT_ENABLE'] == True)
#             assert(data['$AUTO_NEGOTIATION'] == 'PM_AN_FORCE_ENABLE')
#             assert(data['$TX_MTU'] == 1500)
#             assert(data['$RX_MTU'] == 1500)
#             assert(data['$TX_PFC_EN_MAP'] == 1)
#             assert(data['$RX_PFC_EN_MAP'] == 1)
#             assert(data['$TX_PAUSE_FRAME_EN'] == False)
#             assert(data['$RX_PAUSE_FRAME_EN'] == False)
#             assert(data['$RX_PRSR_PRI_THRESH'] == 1)
#             assert(data['$CUT_THROUGH_EN'] == False)
#             assert(data['$PORT_DIR'] == 'PM_PORT_DIR_DEFAULT')
#         elif port == port2.getDevPort():
#             assert(key['$DEV_PORT']['value'] == port2.getDevPort())
#             assert(data['$SPEED'] == port2.getSpeed())
#             assert(data['$FEC'] == port2.getFec())
#             assert(data['$N_LANES'] == n_lanes)
#             assert(data['$PORT_ENABLE'] == True)
#             assert(data['$RX_PRSR_PRI_THRESH'] == 2)
#             assert(data['$LOOPBACK_MODE'] == loop_str_val)

#     logger.info("PortCfgTest: Delete entries for ports %d and %d", port1.getDevPort(), port2.getDevPort())
#     self.port_table.entry_del(
#         target,
#         [self.port_table.make_key([client.KeyTuple('$DEV_PORT', port1.getDevPort())])])
#     self.port_table.entry_del(
#         target,
#         [self.port_table.make_key([client.KeyTuple('$DEV_PORT', port2.getDevPort())])])


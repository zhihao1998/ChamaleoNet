from ipaddress import ip_address

p4 = bfrt.tf_honeypot.pipe
pm = bfrt.port
port = bfrt.pre.port


################ Configure ports ##########################
# enable internal CPU ports 
CPU_PORT = 64
pm.port.add(DEV_PORT=CPU_PORT, SPEED="BF_SPEED_10G", FEC="BF_FEC_TYP_NONE", PORT_ENABLE=True)
port.mod(CPU_PORT, COPY_TO_CPU_PORT_ENABLE=True)

# add the port receiving the incoming traffic
INCOMING_PORT = 160
pm.port.add(DEV_PORT=INCOMING_PORT, SPEED="BF_SPEED_100G", FEC="BF_FEC_TYP_RS", PORT_ENABLE=True)

CONTROLLER_PORT = 140
pm.port.add(DEV_PORT=CONTROLLER_PORT, SPEED="BF_SPEED_10G", FEC="BF_FEC_TYP_NONE", PORT_ENABLE=True)

################ Configure tables ######################

# Set the idle mode as polling for the active_host_tbl, for details see Tofino documentation
active_host_tbl = p4.Ingress.active_host_tbl
active_host_tbl.idle_table_set_poll(enable=True)

################ Configure Mirroring ######################

MIRROR_PORT = 1
SESSION_ID = 12
TRUNCATE_SIZE = 128

mirror_fwd_tbl = p4.Ingress.mirror_fwd
mirror_fwd_tbl.clear()
mirror_fwd_tbl.add_with_set_ing_mirror(ingress_port=CPU_PORT, 
                                   ing_mir_ses=SESSION_ID)

mirror_cfg_tbl = bfrt.mirror.cfg
mirror_cfg_tbl.clear()
mirror_cfg_tbl.add_with_normal(sid=SESSION_ID,
                               session_enable=True,
                               direction="INGRESS",
                               ucast_egress_port=MIRROR_PORT,
                               ucast_egress_port_valid=True,
                               max_pkt_len=TRUNCATE_SIZE)

################ Configure Tables ######################

# Internal network range and mask
internal_nets = [('154.200.0.0', '255.255.0.0')]

internal_ip_check_tbl = p4.Ingress.internal_ip_check
internal_ip_check_tbl.clear()

for net in internal_nets:
    internal_ip_check_tbl.add_with_set_src_internal(src_addr=net[0], src_addr_mask=net[1], MATCH_PRIORITY=10)
    internal_ip_check_tbl.add_with_set_dst_internal(dst_addr=net[0], dst_addr_mask=net[1], MATCH_PRIORITY=10)

# Add the default rule to send packets to the controller
CONTROLLER_DST_MAC = "52:54:00:5b:57:5c"
fwd_controller_tbl = p4.Ingress.fwd_controller_tbl
fwd_controller_tbl.clear()
fwd_controller_tbl.add_with_send_to_controller(ether_type=0x0800,
                                              dst_mac=CONTROLLER_DST_MAC,
                                              out_port=CONTROLLER_PORT)


bfrt.complete_operations()

# print results
print("""
******************* PROGAMMING RESULTS *****************
""")
print ("Table active_host_tbl:")
active_host_tbl.info() 

print ("Table internal_ip_check_tbl:")
internal_ip_check_tbl.info()


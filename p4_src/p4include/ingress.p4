/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

/***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        meta.ing_mir_ses = 0;
        meta.pkt_type = 0;

        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:     parse_ipv4;
            default:            parse_non_ipv4;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.src_ip = hdr.ipv4.src_addr;
        meta.dst_ip = hdr.ipv4.dst_addr;
        meta.ip_protocol = hdr.ipv4.protocol;
        meta.internal_ip = 0;
        meta.internal_port = 0;

        transition select(hdr.ipv4.protocol) {
            IP_PROTO_ICMP: parse_icmp;
            IP_PROTO_TCP:  parse_tcp;
            IP_PROTO_UDP:  parse_udp;
            default:       parse_unknow_ip;
        }
    }
    /* Actually useless, just to avoid warning */
    state parse_non_ipv4 {
        meta.src_ip = 0;
        meta.dst_ip = 0;
        meta.ip_protocol = 0;
        meta.src_port = 0;
        meta.dst_port = 0;
        meta.internal_ip = 0;
        meta.internal_port = 0;
        transition reject;
    }
    state parse_icmp {
        pkt.extract(hdr.icmp);
        meta.src_port = 0;
        meta.dst_port = 0;
        transition accept;
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.src_port = hdr.tcp.src_port;
        meta.dst_port = hdr.tcp.dst_port;
        transition accept;
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        meta.src_port = hdr.udp.src_port;
        meta.dst_port = hdr.udp.dst_port;
        transition accept;
    }
    state parse_unknow_ip {
        meta.src_port = 0;
        meta.dst_port = 0;
        transition accept;
    }
}


 /***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{

    action send_to_cpu() {
        ig_tm_md.ucast_egress_port = CPU_PORT_1;
    }

    action send_to_nf() {
        hdr.ethernet.dst_addr = NF_MAC_ADDR;
        ig_tm_md.ucast_egress_port = PROXY_PORT;
    }

    action set_egress_port(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    @idletime_precision(ENTRY_IDLE_TIMEOUT_NBIT_POLL)
    table active_host_tbl {
        key = {
            meta.internal_ip   : exact;
            meta.internal_port : exact;
            meta.ip_protocol   : exact;
        }
        
        actions = {
            set_egress_port; 
            send_to_cpu;
            send_to_nf;
            drop;
        }
        default_action = send_to_nf();
        size = DEFAULT_TABLE_SIZE;
        idle_timeout = true;
    }
    
    action set_src_internal() {
        meta.internal_ip = meta.src_ip;
        meta.internal_port = meta.src_port;
    }

    action set_dst_internal() {
        meta.internal_ip = meta.dst_ip;
        meta.internal_port = meta.dst_port;
    }

    table internal_ip_check {
        key = {
            hdr.ipv4.src_addr : ternary;
            hdr.ipv4.dst_addr : ternary;
        }
        actions = {
            set_src_internal();
            set_dst_internal();
            NoAction;
        }
        size = 10;
        const default_action = NoAction();
        const entries = {
            (INTERNAL_NET &&& INTERNAL_NET_MASK, _) : set_src_internal();
            (_, INTERNAL_NET &&& INTERNAL_NET_MASK) : set_dst_internal();
        }
    }

    action set_ing_mirror(MirrorId_t ing_mir_ses) {
        meta.ing_mir_ses = ing_mir_ses;

        ig_dprsr_md.mirror_type = MIRROR_TYPE_I2E;
        meta.pkt_type = PKT_TYPE_MIRROR;
    }

    table mirror_fwd {
        key = {
            ig_intr_md.ingress_port : exact;
        }

        actions = {
            set_ing_mirror;
        }

        size = 512;
    }

    action set_normal_pkt() {
        hdr.mirror_bridged_md.setValid();
        hdr.mirror_bridged_md.pkt_type = PKT_TYPE_NORMAL;
    }

    apply {
        set_normal_pkt();
        if (hdr.ipv4.isValid())
        {
            if (internal_ip_check.apply().hit) {
                active_host_tbl.apply();
            }
            else {
                drop();
            }
            // if it's going to be sent to the proxy
            if (ig_dprsr_md.drop_ctl == 0) {
                mirror_fwd.apply();
                ig_dprsr_md.drop_ctl = 1;
            }
        }

    }
}


/*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Mirror() mirror;

    apply {
        if (ig_dprsr_md.mirror_type == MIRROR_TYPE_I2E) {
            mirror.emit<mirror_h>(meta.ing_mir_ses, {meta.pkt_type});
        }
        pkt.emit(hdr);
    }
}
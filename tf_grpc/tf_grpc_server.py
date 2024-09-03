
class TfGRPCServer:
    def __init__(self):
        self.name = "TfGRPCServer"

    def tcp_flow_add_with_drop(self, src_ip, dst_ip, src_port, dst_port):
        print(f"{self.name} add a entry with drop action {(src_ip, dst_ip, src_port, dst_port)}")
        return 0
    
    def tcp_flow_add_with_send(self, src_ip, dst_ip, src_port, dst_port, egress_port):
        print(f"{self.name} add a entry with send action {(src_ip, dst_ip, src_port, dst_port, egress_port)}")
        return 0
    
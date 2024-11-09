import os
import psutil
import time
import copy

cwd = os.path.dirname(os.path.abspath(__file__))
intf_name = 'enp10s0'
sample_interval = 2

def unit_conversion(bit):
    bit = int(bit)
    if bit > 1000:
        res = bit / 1000
        if res < 1000:
            res = float('%.2f' % res)
            return str(res) + 'K'
        elif res < 1000 * 1000:
            res = res / 1000
            res = float('%.2f' % res)
            return str(res) + 'M'
        else:
            res = res / (1000 * 1000)
            res = float('%.2f' % res)
            return str(res) + 'G'
    else:
        return str(bit)

# process to monitor the interface speed
def mon_net_speed():
    net_io = psutil.net_io_counters(pernic=True)[intf_name]
    stats_old = [net_io.bytes_sent, net_io.bytes_recv, net_io.packets_sent, net_io.packets_recv]
    net_stat_log_fp = open(os.path.join(cwd, 'net_stat.csv'), 'w+')
    net_stat_log_fp.write("time,bits_sent,bits_recv,packets_sent,packets_recv\n")

    while True:
        net_io = psutil.net_io_counters(pernic=True)[intf_name]
        stats = [net_io.bytes_sent, net_io.bytes_recv, net_io.packets_sent, net_io.packets_recv]
        diff = [(stats[i]-stats_old[i])*8/sample_interval for i in range(len(stats))]
        net_stat_log_fp.write(f"{time.time()},{diff[0]},{diff[1]},{diff[2]},{diff[3]}\n")
        net_stat_log_fp.flush()

        print(f"Bytes: send: {unit_conversion(diff[0])}bps, recv: {unit_conversion(diff[1])}bps", end=" | ")
        print(f"pps: send: {unit_conversion(diff[2])}pps, recv: {unit_conversion(diff[3])}pps")
        stats_old = copy.deepcopy(stats)
        time.sleep(sample_interval)


mon_net_speed()
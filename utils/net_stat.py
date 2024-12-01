import os
import psutil
import time
import copy

cwd = os.path.dirname(os.path.abspath(__file__))
intf_name = 'enp10s0'
sample_interval = 10

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

def get_mem_size(process_name):
    total_mem = 0
    total_cpu = 0
    cpu_num = 0
    for proc in psutil.process_iter():
        try:
            if process_name == proc.name():
                process = psutil.Process(proc.pid)
                total_mem += process.memory_info().rss
                total_cpu += process.cpu_percent(interval=0.1)
                cpu_num += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            print("Error: ", proc)
    return total_mem, total_cpu, cpu_num


# process to monitor the interface speed
def mon_net_speed():
    net_io = psutil.net_io_counters(pernic=True)[intf_name]
    stats_old = [net_io.bytes_sent, net_io.bytes_recv, net_io.packets_sent, net_io.packets_recv]
    net_stat_log_fp = open(os.path.join(cwd, '../log/net_stat_recv.csv'), 'w+')
    net_stat_log_fp.write("time,bits_sent,bits_recv,packets_sent,packets_recv,mem_usage,cpu_usage,cpu_num\n")

    while True:
        net_io = psutil.net_io_counters(pernic=True)[intf_name]
        stats = [net_io.bytes_sent, net_io.bytes_recv, net_io.packets_sent, net_io.packets_recv]
        diff = [(stats[i]-stats_old[i])/sample_interval for i in range(len(stats))]
        diff[0] = diff[0] * 8 # byte -> bit
        diff[1] = diff[1] * 8
        
        mem_usage, cpu_usage, cpu_num = get_mem_size('tsdn')
        net_stat_log_fp.write(f"{time.time()},{diff[0]},{diff[1]},{diff[2]},{diff[3]},{mem_usage},{cpu_usage},{cpu_num}\n")
        net_stat_log_fp.flush()

        print(f"Bytes: send: {unit_conversion(diff[0])}bps, recv: {unit_conversion(diff[1])}bps", end=" | ")
        print(f"pps: send: {unit_conversion(diff[2])}pps, recv: {unit_conversion(diff[3])}pps", end=" | ")
        print(f"mem_usage: {unit_conversion(mem_usage)} | cpu_usage: {cpu_usage}%")
        stats_old = copy.deepcopy(stats)
        time.sleep(sample_interval)


mon_net_speed()
import pickle
import time
from collections import Counter
from datetime import datetime

with open('/home/zhihaow/codes/honeypot_c_controller/log/20241230_16-10-00_bfrt_rule.pkl', 'rb') as f:
    data = pickle.load(f)
    print(len(data))
    for k, v in data.most_common(20):
        print(k, v)

# now = datetime.now()
# cur_date = now.strftime("%Y%m%d")
# cur_hour = now.hour
# cur_min = now.minute
# cur_sec = now.second
# cur_time = ''.join([cur_date, '_', str(cur_hour), '-', str(cur_min), '-', str(cur_sec)])
# print(cur_time)
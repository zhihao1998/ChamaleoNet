import pickle
from collections import Counter
import glob
import os

# backup the merged counter
if os.path.exists('/home/zhihaow/codes/honeypot_c_controller/log/rule_counter/0000000-merged_counter.pkl'):
    os.system('cp /home/zhihaow/codes/honeypot_c_controller/log/rule_counter/0000000-merged_counter.pkl /home/zhihaow/codes/honeypot_c_controller/log/rule_counter/0000000-merged_counter-backup.pkl')
    old_merged_counter = pickle.load(open('/home/zhihaow/codes/honeypot_c_controller/log/rule_counter/0000000-merged_counter.pkl', 'rb'))
else:
    old_merged_counter = Counter()

counter_file_list = sorted(glob.glob('/home/zhihaow/codes/honeypot_c_controller/log/rule_counter/*.pkl'))

for counter_file in counter_file_list:
    if counter_file == '/home/zhihaow/codes/honeypot_c_controller/log/rule_counter/0000000-merged_counter.pkl':
        continue
    with open(counter_file, 'rb') as cf:
        print(f'Merging {counter_file}', end=' ')
        counter = pickle.load(cf)
        old_merged_counter += counter
        print(f'Merged counter size: {len(old_merged_counter)}, Top 2: {old_merged_counter.most_common(2)}')

with open('/home/zhihaow/codes/honeypot_c_controller/log/rule_counter/0000000-merged_counter.pkl', 'wb') as f:
    pickle.dump(old_merged_counter, f)

for counter_file in counter_file_list:
    if '0000000-merged_counter' in counter_file:
        continue
    os.remove(counter_file)
    print(f'Removed {counter_file}')


# scp to server
os.system('scp /home/zhihaow/codes/honeypot_c_controller/log/rule_counter/0000000-merged_counter.pkl zwang@bigdatalab.polito.it:/home/students/zwang/tsdn_followup/stats')

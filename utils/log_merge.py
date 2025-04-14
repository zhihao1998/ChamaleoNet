import glob
import os

# leave the latest one, since it is still being written
log_file_list = sorted(glob.glob('/home/zhihaow/codes/honeypot_c_controller/log/*stat.csv'))[:-1]

if len(log_file_list) < 2:
    exit()

start_time = '_'.join(log_file_list[0].split('/')[-1].split('_')[0:2])
end_time = '_'.join(log_file_list[-1].split('/')[-1].split('_')[0:2])

with open(f'/home/zhihaow/codes/honeypot_c_controller/log/archived/{start_time}_{end_time}_merged_stat.csv', 'w') as f:
    for log_file in log_file_list:
        with open(log_file, 'r') as f_log:
            # write header only once
            if log_file == log_file_list[0]:
                f.write(f_log.readline())
            # remove the header
            f_log.readline()
            # write the rest to merged_stat.csv
            f.write(f_log.read())

# remove the original log files
for log_file in log_file_list:
    os.remove(log_file)

# # merge with all the previous merged files
# merged_file_list = sorted(glob.glob('/home/zhihaow/codes/honeypot_c_controller/log/archived/*merged_stat.csv'))
# if len(merged_file_list) < 2:
#     exit()

# start_time = '_'.join(merged_file_list[0].split('/')[-1].split('_')[0:2])
# end_time = '_'.join(merged_file_list[-1].split('/')[-1].split('_')[2:4])

# with open(f'/home/zhihaow/codes/honeypot_c_controller/log/archived/{start_time}_{end_time}_merged_stat.csv', 'w') as f:
#     for merged_file in merged_file_list:
#         with open(merged_file, 'r') as f_merged:
#             # write header only once
#             if merged_file == merged_file_list[0]:
#                 f.write(f_merged.readline())
#             # remove the header
#             f_merged.readline()
#             # write the rest to merged_stat.csv
#             f.write(f_merged.read())

# # remove the original merged files
# for merged_file in merged_file_list:
#     os.remove(merged_file)
#!/home/sv2859527/.train/bin/python
#/usr/bin/env python3
from scapy.all import sniff
import polars as pl
import numpy as np
from datetime import datetime
import statistics
import time
import threading
import os
import sys
import lightgbm as lgb

# Define a dictionary to store flow data
flow_data = {}
stop_event = threading.Event()

def save_screen_state():
    sys.stdout.write('\033[s')  # Save cursor position
    sys.stdout.write('\033[?1049h')  # Save screen (alternate buffer)
    sys.stdout.flush()

# Function to restore the screen state
def restore_screen_state():
    sys.stdout.write('\033[?1049l')  # Restore screen (alternate buffer)
    sys.stdout.write('\033[u')  # Restore cursor position
    sys.stdout.flush()


def clear_region(width, height):
    """
    Clears a rectangular region of the terminal by writing spaces.

    :param width: Number of characters wide to clear.
    :param height: Number of lines high to clear.
    """
    # ANSI escape codes to move the cursor
    cursor_up = '\033[A'
    cursor_down = '\033[B'
    cursor_home = '\033[H'
    clear_line = '\033[K'

    # Move the cursor to the top-left of the region
    sys.stdout.write(cursor_home)

    # Clear the region line by line
    for _ in range(height):
        sys.stdout.write(' ' * width + clear_line)
        sys.stdout.write(cursor_down)

    # Move the cursor back to the original position
    sys.stdout.write(cursor_up * height)
    sys.stdout.flush()

def get_terminal_size():
    """Get the current size of the terminal window."""
    try:
        # Attempt to get terminal size using the `os` module
        import shutil
        columns, rows = shutil.get_terminal_size()
        return columns, rows
    except:
        # Fallback in case `shutil` fails
        return 80, 24  # Default size

def print_dataframe(df):
    """Print the DataFrame, overwriting the previous content."""
    columns, rows = get_terminal_size()

    #clear region
    clear_region(columns, rows)
    
    # Calculate the maximum number of rows to display
    df_string = str(df) + "\n"
    
    # Clear the current line (optional)
    sys.stdout.write('\033[K') 

    # Move cursor to the top-left of the terminal
    sys.stdout.write('\033[H') 
    
    # Print the DataFrame
    sys.stdout.write(df_string)
    sys.stdout.flush()

def process_packet(packet):
    global flow_data

    if packet.haslayer('IP'):
        # Extract information from the packet
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        protocol = packet['IP'].proto if packet['IP'].proto in [6, 17] else 0
        #ip_header_length  in bytes
        ihl = packet['IP'].ihl * 4
        length = len(packet)
        timestamp = datetime.now()
        
        # Initialize flow key based on src/dst IP and protocol
        flow_key = (src_ip, dst_ip, protocol)
        flow_key_interchange = (dst_ip, src_ip, protocol)

        # Initialize flow data if not present
        if flow_key not in flow_data:
            if flow_key_interchange not in flow_data :
                flow_data[flow_key] = {
                    'start_time': timestamp,
                    'total_fwd_packets': 0,
                    'total_bwd_packets': 0,
                    'fwd_packet_lengths': [],
                    'bwd_packet_lengths': [],
                    'packet_times': [],
                    'packet_lengths': [],
                    'fwd_iat': [],
                    'bwd_iat': [],
                    'fwd_header_lengths': [],
                    'bwd_header_lengths': [],
                    'fwd_flags': {'PSH': 0, 'URG': 0},
                    'bwd_flags': {'PSH': 0, 'URG': 0},
                    'flags': {'FIN': 0, 'SYN': 0, 'RST': 0, 'ACK': 0, 'CWR': 0, 'ECE': 0},
                    'fwd_segment_lengths': [],
                    'bwd_segment_lengths': [],
                    'subflow_fwd_packets': [],
                    'subflow_bwd_packets': [],
                    'active': [],
                    'idle': [],
                    'fwd_act_data_packets': 0,
                    'fwd_first_bulk_time': None,
                    'fwd_last_bulk_time': None,
                    'bwd_first_bulk_time': None,
                    'bwd_last_bulk_time': None,
                }
            else: 
                flow_key = flow_key_interchange

        # Update flow data
        flow = flow_data[flow_key]

        # Update counts and lists based on the packet's direction (example condition for forward and backward)
        if flow_key[0] == packet['IP'].src:  # Forward packets
            flow['total_fwd_packets'] += 1
            flow['fwd_header_lengths'].append(ihl)
            flow['fwd_packet_lengths'].append(length)
             # Check if the packet has payload (for TCP, if payload size > 0)
            if flow['fwd_first_bulk_time'] is None:
                flow['fwd_first_bulk_time'] = timestamp
                flow['fwd_last_bulk_time'] = timestamp
            if packet.haslayer('TCP') and len(packet['TCP'].payload) > 0:
                flow['fwd_act_data_packets'] += 1  # Increment active data packets

            if 'fwd_first_bulk_time' not in flow or flow['fwd_first_bulk_time'] is None:
               flow['fwd_first_bulk_time'] = datetime.now()  # Set initial bulk time

            flow['fwd_last_bulk_time'] = datetime.now()  # Update last bulk time
            if flow['packet_times']:
                    flow['fwd_iat'].append((timestamp - flow['packet_times'][-1]).total_seconds())
        else:  # Backward packets
            flow['total_bwd_packets'] += 1
            flow['bwd_header_lengths'].append(ihl)
            flow['bwd_packet_lengths'].append(length)
            # Bulk time updates for backward packets
            if 'bwd_first_bulk_time' not in flow or flow['bwd_first_bulk_time'] is None:
                 flow['bwd_first_bulk_time'] = datetime.now()  # Set initial bulk time
            flow['bwd_last_bulk_time'] = datetime.now()  # Update last bulk time
            if flow['packet_times']:
                flow['bwd_iat'].append((timestamp - flow['packet_times'][-1]).total_seconds())
            if flow['bwd_first_bulk_time'] is None:
                flow['bwd_first_bulk_time'] = timestamp
                flow['bwd_last_bulk_time'] = timestamp

        flow['packet_times'].append(timestamp)
        flow['packet_lengths'].append(length)

         # Initialize time_diff before using it
        time_diff = None
        idle_threshold = 1
        # Calculate time_diff only if there are at least two timestamps
        if len(flow['packet_times']) > 1:
            time_diff = (flow['packet_times'][-1] - flow['packet_times'][-2]).total_seconds()

            # Determine if the packet is active or idle
            if time_diff is not None and time_diff <= idle_threshold:
                flow['active'].append(time_diff)
            elif time_diff is not None:
                flow['idle'].append(time_diff)


        # TCP flags (if TCP packet)
        if packet.haslayer('TCP'):

            # Get the TCP header length 
            #dataofs is in 32-bit words
            tcp_header_length = packet['TCP'].dataofs * 4  
            # Get the payload size
            payload_size = len(packet['TCP'].payload)

            # Calculate the TCP segment size
            segment_size = tcp_header_length + payload_size
            tcp_flags = packet['TCP'].flags

            # MPTCP option
            tcp_options = packet['TCP'].options
            mptcp_present = any(opt[0] == 'MPTCP' for opt in tcp_options)

            if flow_key[0] == packet['IP'].src:  # Forward direction
                flow['fwd_flags']['PSH'] += int(tcp_flags & 0x08 != 0)
                flow['fwd_flags']['URG'] += int(tcp_flags & 0x20 != 0)
                flow['fwd_segment_lengths'].append(segment_size)

                if mptcp_present:
                    flow['subflow_fwd_packets'].append(len(packet))

            else:  # Backward direction
                flow['bwd_flags']['PSH'] += int(tcp_flags & 0x08 != 0)
                flow['bwd_flags']['URG'] += int(tcp_flags & 0x20 != 0)
                flow['bwd_segment_lengths'].append(segment_size)
                if mptcp_present:
                    flow['subflow_bwd_packets'].append(len(packet))

            #Flag counts
            flow['flags']['FIN'] += int(tcp_flags & 0x01 != 0)
            flow['flags']['SYN'] += int(tcp_flags & 0x02 != 0)
            flow['flags']['RST'] += int(tcp_flags & 0x04 != 0)
            flow['flags']['ACK'] += int(tcp_flags & 0x10 != 0)
            flow['flags']['CWR'] += int(tcp_flags & 0x80 != 0)
            flow['flags']['ECE'] += int(tcp_flags & 0x40 != 0)

def calculate_features():
    features = []
    for flow_key, data in flow_data.items():
        active_values = data.get('active', [])
        idle_values = data.get('idle', [])
        duration = (datetime.now() - data['start_time']).total_seconds()
        total_fwd_packets = data['total_fwd_packets']
        total_bwd_packets = data['total_bwd_packets']
        fwd_packet_lengths = data['fwd_packet_lengths']
        bwd_packet_lengths = data['bwd_packet_lengths']
        fwd_iat = data['fwd_iat']
        bwd_iat = data['bwd_iat']
        total_packets = total_fwd_packets + total_bwd_packets
        total_bytes = sum(data['packet_lengths'])

        # Forward packet length statistics
        fwd_packet_length_total = sum(fwd_packet_lengths) if fwd_packet_lengths else 0
        fwd_packet_length_max = max(fwd_packet_lengths) if fwd_packet_lengths else 0
        fwd_packet_length_min = min(fwd_packet_lengths) if fwd_packet_lengths else 0
        fwd_packet_length_mean = sum(fwd_packet_lengths) / len(fwd_packet_lengths) if fwd_packet_lengths else 0
        fwd_packet_length_std = statistics.stdev(fwd_packet_lengths) if len(fwd_packet_lengths) > 1 else 0

        # Backward packet length statistics
        bwd_packet_length_total = sum(bwd_packet_lengths) if bwd_packet_lengths else 0
        bwd_packet_length_max = max(bwd_packet_lengths) if bwd_packet_lengths else 0
        bwd_packet_length_min = min(bwd_packet_lengths) if bwd_packet_lengths else 0
        bwd_packet_length_mean = sum(bwd_packet_lengths) / len(bwd_packet_lengths) if bwd_packet_lengths else 0
        bwd_packet_length_std = statistics.stdev(bwd_packet_lengths) if len(bwd_packet_lengths) > 1 else 0

        # Flow-level features
        flow_bytes_per_s = total_bytes / duration if duration > 0 else 0
        flow_packets_per_s = total_packets / duration if duration > 0 else 0

        # Inter-arrival times (IAT)
        iat_list = [(data['packet_times'][i] - data['packet_times'][i-1]).total_seconds() 
                    for i in range(1, len(data['packet_times']))]
        iat_mean = sum(iat_list) / len(iat_list) if iat_list else 0
        iat_std = statistics.stdev(iat_list) if len(iat_list) > 1 else 0
        iat_max = max(iat_list) if iat_list else 0
        iat_min = min(iat_list) if iat_list else 0

        # Forward IAT statistics
        fwd_iat_total = sum(fwd_iat) if fwd_iat else 0
        fwd_iat_mean = fwd_iat_total / len(fwd_iat) if fwd_iat else 0
        fwd_iat_total = sum(fwd_iat) if fwd_iat else 0
        fwd_iat_mean = fwd_iat_mean if fwd_iat else 0
        fwd_iat_std = statistics.stdev(fwd_iat) if len(fwd_iat) > 1 else 0
        fwd_iat_max = max(fwd_iat) if fwd_iat else 0
        fwd_iat_min = min(fwd_iat) if fwd_iat else 0

        # Backward IAT statistics
        bwd_iat_total = sum(bwd_iat) if bwd_iat else 0
        bwd_iat_mean = bwd_iat_total / len(bwd_iat) if bwd_iat else 0
        bwd_iat_total = sum(bwd_iat) if bwd_iat else 0
        bwd_iat_mean = bwd_iat_mean if fwd_iat else 0
        bwd_iat_std = statistics.stdev(bwd_iat) if len(bwd_iat) > 1 else 0
        bwd_iat_max = max(bwd_iat) if bwd_iat else 0
        bwd_iat_min = min(bwd_iat) if bwd_iat else 0

        #Header lengths
        fwd_header_length = sum(data['fwd_header_lengths'])
        bwd_header_length = sum(data['bwd_header_lengths'])
        header_length_mean = sum([fwd_header_length + bwd_header_length]) / sum([len(data['fwd_header_lengths']) + len(data['bwd_header_lengths'])])

        # Flag counts (TCP)
        fwd_flags = data['fwd_flags']
        bwd_flags = data['bwd_flags']
        flags = data['flags']

        #Packets/sec
        fwd_packets_per_sec = total_fwd_packets / duration if duration else 0
        bwd_packets_per_sec = total_bwd_packets / duration if duration else 0

        #Down/up (ratio)
        down_up_ratio = bwd_packet_length_total / fwd_packet_length_total if fwd_packet_length_total else 0

        #Packect statistics
        packet_length_min = min(data['packet_lengths'])
        packet_length_max = max(data['packet_lengths'])
        packet_length_mean = sum(data['packet_lengths'])/ len(data['packet_lengths']) if data['packet_lengths'] else 0
        packet_length_std = statistics.stdev(data['packet_lengths']) if len(data['packet_lengths']) > 1 else 0
        packet_length_var = statistics.variance(data['packet_lengths']) if len(data['packet_lengths']) > 1 else 0

        #Segment averages
        avg_fwd_segment_size = sum(data['fwd_segment_lengths']) / len(data['fwd_segment_lengths']) if data['fwd_segment_lengths'] else 0
        avg_bwd_segment_size = sum(data['bwd_segment_lengths']) / len(data['bwd_segment_lengths']) if data['bwd_segment_lengths'] else 0

        #SUBFLOW PACKETS AND BYTES

        subflow_fwd_packets = len(data['subflow_fwd_packets']) / data.get('subflow_count', 1)
        # Subflow backward packets calculation
        subflow_bwd_packets = len(data['subflow_bwd_packets']) / data.get('subflow_count', 1)
        # Subflow forward bytes calculation (ensure you have a similar structure)
        subflow_fwd_bytes = sum(data['fwd_packet_lengths']) / data.get('subflow_count', 1)
        # Subflow backward bytes calculation (ensure you have a similar structure)
        subflow_bwd_bytes = sum(data['bwd_packet_lengths']) / data.get('subflow_count', 1)
        #Forward act data packets
        fwd_act_data_packets = data.get('fwd_act_data_packets', 0)

        #fwd seg size min
        fwd_seg_size_min = min(data.get('fwd_segment_lengths',[]), default=0)

        
         #Active features(mean, std, max, min)
        if active_values:
            active_min = min(active_values)
            active_max = max(active_values)
            active_mean = statistics.mean(active_values)
            active_std = statistics.pstdev(active_values) if len(active_values) > 1 else 0
        else:
            active_min = active_max = active_mean = active_std = 0

        #Idle features(mean,max,min,std)
        if idle_values:
            idle_min = min(idle_values)
            idle_max = max(idle_values)
            idle_mean = statistics.mean(idle_values)
            idle_std = statistics.pstdev(idle_values) if len(idle_values) > 1 else 0
        else:
            idle_min = idle_max = idle_mean = idle_std = 0

        #forward bulk stats
        fwd_bulk_bytes = sum(data['fwd_packet_lengths']) if data['fwd_packet_lengths'] else 0
        fwd_bulk_packets = len(data['fwd_packet_lengths']) if data['fwd_packet_lengths'] else 0
        fwd_bulk_duration = 0  # Default bulk duration
        if data.get('fwd_first_bulk_time') and data.get('fwd_last_bulk_time'):
                fwd_bulk_duration = (data['fwd_last_bulk_time'] - data['fwd_first_bulk_time']).total_seconds()

        fwd_avg_bytes_bulk = fwd_bulk_bytes / fwd_bulk_packets if fwd_bulk_packets > 0 else 0
        fwd_avg_packets_bulk = fwd_bulk_packets / fwd_bulk_bytes if fwd_bulk_packets > 0 else 0
        fwd_avg_bulk_rate = fwd_bulk_bytes / fwd_bulk_duration if fwd_bulk_duration > 0 else 0

          #backward bulk stats
        bwd_bulk_bytes = sum(data['bwd_packet_lengths']) if data['bwd_packet_lengths'] else 0
        bwd_bulk_packets = len(data['bwd_packet_lengths']) if data['bwd_packet_lengths'] else 0
        bwd_bulk_duration = 0  # Default bulk duration
        if data.get('bwd_first_bulk_time') and data.get('bwd_last_bulk_time'):
            bwd_bulk_duration = (data['bwd_last_bulk_time'] - data['bwd_first_bulk_time']).total_seconds()

        bwd_avg_bytes_bulk = bwd_bulk_bytes / bwd_bulk_packets if bwd_bulk_packets > 0 else 0
        bwd_avg_packets_bulk = bwd_bulk_packets / bwd_bulk_bytes if bwd_bulk_packets > 0 else 0
        bwd_avg_bulk_rate = bwd_bulk_bytes / bwd_bulk_duration if bwd_bulk_duration > 0 else 0

        # Calculate Init Fwd Win Bytes and Init Bwd Win Bytes
        init_fwd_win_bytes = data['fwd_packet_lengths'][0] if data['fwd_packet_lengths'] else 0
        init_bwd_win_bytes = data['bwd_packet_lengths'][0] if data['bwd_packet_lengths'] else 0

        features.append({
            'src_ip': flow_key[0],
            'dst_ip': flow_key[1],
            'Protocol': flow_key[2],
            'Flow Duration': int(duration), 
            'Total Fwd Packets': total_fwd_packets,
            'Total Backward Packets': total_bwd_packets,
            'Fwd Packets Length Total': fwd_packet_length_total,
            'Bwd Packet Length Total': bwd_packet_length_total,
            'Fwd Packet Length Max': fwd_packet_length_max,
            'Fwd Packet Length Min': fwd_packet_length_min,
            'Fwd Packet Length Mean': fwd_packet_length_mean,
            'Fwd Packet Length Std': fwd_packet_length_std,
            'Bwd Packet Length Max': bwd_packet_length_max,
            'Bwd Packet Length Min': bwd_packet_length_min,
            'Bwd Packet Length Mean': bwd_packet_length_mean,
            'Bwd Packet Length Std': bwd_packet_length_std,
            'Flow Bytes/s': flow_bytes_per_s,
            'Flow Packets/s': flow_packets_per_s,
            'Flow IAT Mean': iat_mean,
            'Flow IAT Std': iat_std,
            'Flow IAT Max': iat_max,
            'Flow IAT Min': iat_min,
            'Fwd IAT Total': fwd_iat_total,
            'Fwd IAT Mean': fwd_iat_mean,
            'Fwd IAT Std': fwd_iat_std,
            'Fwd IAT Max': fwd_iat_max,
            'Fwd IAT Min': fwd_iat_min,
            'Bwd IAT Total': bwd_iat_total,
            'Bwd IAT Mean': bwd_iat_mean,
            'Bwd IAT Std': bwd_iat_std,
            'Bwd IAT Max': bwd_iat_max,
            'Bwd IAT Min': bwd_iat_min,
            'Fwd PSH Flags': fwd_flags['PSH'],
            'Fwd URG Flags': fwd_flags['URG'],
            'Bwd PSH Flags': bwd_flags['PSH'],
            'Bwd URG Flags': bwd_flags['URG'],
            'Fwd Header Length': fwd_header_length,
            'Bwd Header Length': bwd_header_length,
            'Fwd Packets/s': fwd_packets_per_sec,
            'Bwd Packets/s': bwd_packets_per_sec,
            'Packet Length Min': packet_length_min, 
            'Packet Length Max': packet_length_max, 
            'Packet Length Mean': packet_length_mean - header_length_mean,
            'Packet Length Std': packet_length_std, 
            'Packet Length Variance': packet_length_var, 
            'FIN count': flags['FIN'],
            'SYN count': flags['SYN'],
            'RST count': flags['RST'],
            'PSH count': fwd_flags['PSH'] + bwd_flags['PSH'],
            'ACK count': flags['ACK'],
            'URG count': fwd_flags['URG'] + bwd_flags['URG'],
            'CWE count': flags['ACK'],
            'ECE count': flags['ACK'],
            'Down_up_ratio': down_up_ratio,
            'Avg Packet Size': packet_length_mean, 
            'Avg Fwd Segment Size': avg_fwd_segment_size,
            'Avg Bwd Segment Size': avg_bwd_segment_size,
            'Fwd Avg Bytes/Bulk': fwd_avg_bytes_bulk ,
            'Fwd Avg Packets/Bulk': fwd_avg_packets_bulk,
            'Fwd Avg Bulk Rate': fwd_avg_bulk_rate,
            'Bwd Avg Bytes/Bulk': bwd_avg_bytes_bulk,
            'Bwd Avg Packets/Bulk': bwd_avg_packets_bulk,
            'Bwd Avg Bulk Rate': bwd_avg_bulk_rate,
            'Subflow Fwd Packets': subflow_fwd_packets,
            'Subflow Fwd Bytes': subflow_fwd_bytes,
            'Subflow Bwd Packets': subflow_bwd_packets,
            'Subflow Bwd Bytes': subflow_bwd_bytes,
            'Init Fwd Win Bytes': init_fwd_win_bytes,
            'Init Bwd Win Bytes': init_bwd_win_bytes,
            'Fwd Act Data Packets': fwd_act_data_packets,
            'Fwd Seg Size Min': fwd_seg_size_min,
            'Active Mean': active_mean ,
            'Active Std': active_std,
            'Active Max': active_max,
            'Active Min': active_min,
            'Idle Mean':idle_mean ,
            'Idle Std':idle_std,
            'Idle Max':idle_max,
            'Idle Min':idle_min,
        })

    # Create a Polars DataFrame from the features list
    df = pl.DataFrame(features)
    return df

def periodic_task():
    """Function to capture and print features periodically."""
    global stop_event
    start_time = time.time()
    
    # All the classes in the trained dataset
    labels = ['Benign', 'Bot', 'Brute Force -Web', 'Brute Force -XSS', 'DDOS attack-HOIC', 'DDOS attack-LOIC-UDP', 'DDoS attacks-LOIC-HTTP', 'DoS attacks-GoldenEye', 'DoS attacks-Hulk', 'DoS attacks-SlowHTTPTest', 'DoS attacks-Slowloris', 'FTP-BruteForce', 'Infilteration', 'SQL Injection', 'SSH-Bruteforce']
    #load model
    model = lgb.Booster(model_file="watson")
    
    while not stop_event.is_set():
        current_time = time.time()
        if current_time - start_time >= 5:
            # Calculate features and print DataFrame
            features_df = calculate_features()
            
            #predict and update df
            #call y_pred
            y_pred = model.predict(features_df.drop(['src_ip', 'dst_ip']), num_iteration=model.best_iteration)
            y_pred = np.argmax(y_pred, axis=1)

            #try printing y_pred
            preds = (labels[i] for i in y_pred)
            Label = pl.Series('Label', list(preds))

            
            print_dataframe(features_df.with_columns(Label))
            
            # Save to CSV
            features_df.write_csv("packet.csv")
            
            
            # Reset start time for the next interval
            start_time = current_time

        # Continue packet sniffing
        sniff(prn=process_packet, timeout=1, store=0)  # Adjust timeout as needed

def main():
    global stop_event
    columns, rows = get_terminal_size()
    
    #save screen state
    save_screen_state()


    #clear manually
    clear_region(columns, rows)
    print('')
    print('Starting packet capture...')

    # Start packet capturing in a separate thread
    capture_thread = threading.Thread(target=periodic_task)
    capture_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping packet capture...")
        stop_event.set()
        capture_thread.join()  # Ensure the thread has finished
    finally:
        restore_screen_state()


if __name__ == '__main__':
    main()


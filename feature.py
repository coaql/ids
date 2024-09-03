from scapy.all import sniff
import polars as pl
from datetime import datetime
import statistics
import time

# Define a dictionary to store flow data
flow_data = {}

def process_packet(packet):
    global flow_data

    if packet.haslayer('IP'):
        # Extract information from the packet
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        protocol = packet['IP'].proto
        length = len(packet)

        # Initialize flow key based on src/dst IP and protocol
        flow_key = (src_ip, dst_ip, protocol)

        # Initialize flow data if not present
        if flow_key not in flow_data:
            flow_data[flow_key] = {
                'start_time': datetime.now(),
                'total_fwd_packets': 0,
                'total_bwd_packets': 0,
                'fwd_packet_lengths': [],
                'bwd_packet_lengths': [],
                'packet_times': [],
                'packet_lengths': []
            }

        # Update flow data
        flow = flow_data[flow_key]
        # Update counts and lists based on the packet's direction
        if packet['IP'].flags & 0x02 == 0:  # Example condition for forward packets
            flow['total_fwd_packets'] += 1
            flow['fwd_packet_lengths'].append(length)
        else:  # Example condition for backward packets
            flow['total_bwd_packets'] += 1
            flow['bwd_packet_lengths'].append(length)
        
        flow['packet_times'].append(datetime.now())
        flow['packet_lengths'].append(length)

def calculate_features():
    features = []
    for flow_key, data in flow_data.items():
        duration = (datetime.now() - data['start_time']).total_seconds()
        total_fwd_packets = data['total_fwd_packets']
        total_bwd_packets = data['total_bwd_packets']
        fwd_packet_lengths = data['fwd_packet_lengths']
        bwd_packet_lengths = data['bwd_packet_lengths']

        # Calculate example features
        fwd_packet_length_max = max(fwd_packet_lengths) if fwd_packet_lengths else 0
        fwd_packet_length_min = min(fwd_packet_lengths) if fwd_packet_lengths else 0
        fwd_packet_length_mean = sum(fwd_packet_lengths) / len(fwd_packet_lengths) if fwd_packet_lengths else 0
        fwd_packet_length_std = statistics.stdev(fwd_packet_lengths) if len(fwd_packet_lengths) > 1 else 0

        bwd_packet_length_max = max(bwd_packet_lengths) if bwd_packet_lengths else 0
        bwd_packet_length_min = min(bwd_packet_lengths) if bwd_packet_lengths else 0
        bwd_packet_length_mean = sum(bwd_packet_lengths) / len(bwd_packet_lengths) if bwd_packet_lengths else 0
        bwd_packet_length_std = statistics.stdev(bwd_packet_lengths) if len(bwd_packet_lengths) > 1 else 0

        # Add more feature calculations here...

        features.append({
            'src_ip': flow_key[0],
            'dst_ip': flow_key[1],
            'protocol': flow_key[2],
            'flow_duration': duration,
            'total_fwd_packets': total_fwd_packets,
            'total_bwd_packets': total_bwd_packets,
            'fwd_packet_length_max': fwd_packet_length_max,
            'fwd_packet_length_min': fwd_packet_length_min,
            'fwd_packet_length_mean': fwd_packet_length_mean,
            'fwd_packet_length_std': fwd_packet_length_std,
            'bwd_packet_length_max': bwd_packet_length_max,
            'bwd_packet_length_min': bwd_packet_length_min,
            'bwd_packet_length_mean': bwd_packet_length_mean,
            'bwd_packet_length_std': bwd_packet_length_std,
            # Add more features here...
        })

    # Create a Polars DataFrame from the features list
    df = pl.DataFrame(features)
    return df

def main():
    print('Starting packet capture...')

    #Set interval in seconds
    interval = 10

    start_time = time.time()


    def periodic_task():
        nonlocal start_time
        """ Function to capture and print features periodically. """
        while True:
            current_time = time.time()
            if current_time - start_time >= interval:
                # Calculate features and print DataFrame
                features_df = calculate_features()
                print("Features DataFrame:")
                print(features_df)
                
                # Reset start time for the next interval
                start_time = current_time

            # Continue packet sniffing
            sniff(prn=process_packet, timeout=1, store=0)  # Adjust timeout as needed

    periodic_task()

if __name__ == '__main__':
    main()


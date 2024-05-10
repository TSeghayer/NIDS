from scapy.all import rdpcap, IP, TCP, UDP
from datetime import datetime
import pandas as pd
from decimal import Decimal, ROUND_HALF_UP
from collections import Counter

class Data_Pro:
    def __init__(self):
        self.current_pcap_file_path = r'C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Packets\Full\1Order.pcapng'
        self.baseline_pcap_file_path = r'C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Packets\Running\running.pcapng'
        self.logs = []

    def _calculate_throughput(self, pcap_path):
        packets = rdpcap(pcap_path)
        total_bytes = sum(len(packet) for packet in packets)
        total_throughput = total_bytes * 8 / (packets[-1].time - packets[0].time) / 1000  # Throughput in kbps
        return Decimal(total_throughput).quantize(Decimal('0.001'), rounding=ROUND_HALF_UP)

    def get_ip(self, pcap_path):
        packets = rdpcap(pcap_path)
        ip_addresses = set()
        for packet in packets:
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                ip_addresses.update([ip_src, ip_dst])
        return ip_addresses
    

    def generate_baseline_values(self):
        baseline_ips = self.get_ip(self.baseline_pcap_file_path)
        baseline_throughput = self._calculate_throughput(self.baseline_pcap_file_path)
        return baseline_ips, baseline_throughput
    
    def top_speakers(self, pcap_path, count=5):
        packets = rdpcap(pcap_path)
        ip_count = Counter()

        for packet in packets:
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                ip_count[ip_src] += len(packet)
                ip_count[ip_dst] += len(packet)

        top_ips = ip_count.most_common(count) 
        return top_ips    
    
    def top_protocols(self, pcap_path, count=5):
        packets = rdpcap(pcap_path)
        protocol_count = Counter()

        for packet in packets:
            if TCP in packet:
                protocol_count['TCP'] += 1
            elif UDP in packet:
                protocol_count['UDP'] += 1
            elif IP in packet:  # Fallback if it's just IP without TCP/UDP
                protocol_count['IP'] += 1
            else:
                protocol_count[packet.__class__.__name__] += 1  # General case for other protocols

        top_protocols = protocol_count.most_common(count)
        return top_protocols 

    def generate_throughput_data(self, pcap_path, interval='T'):
        packets = rdpcap(pcap_path)
        times = []
        sizes = []

        for packet in packets:
            if IP in packet:
                # Ensure packet.time is a float
                packet_time = datetime.fromtimestamp(float(packet.time))
                times.append(packet_time)
                sizes.append(len(packet))

        df = pd.DataFrame({'Time': times, 'Size': sizes})
        df.set_index('Time', inplace=True)
        df = df.resample(interval).sum()  # Resample and sum over 'interval', typically 'T' for per minute
        df['Throughput_Bytes'] = df['Size']  # Keeping the throughput in bytes

        return df.reset_index()  

    class Security_Events:
        def __init__(self, parent):
            self.parent = parent

        def detect_new_ip_addresses(self, baseline_ips):
            comparison_ips = self.parent.get_ip(self.parent.current_pcap_file_path)
            new_ips = [ip for ip in comparison_ips if ip not in baseline_ips]
            if new_ips:
                message = f"Alert: New IP addresses detected: {', '.join(new_ips)}."
                self.parent.logs.append(message)
            

        def detect_throughput_anomaly(self, baseline_throughput, threshold=0.05):
            comparison_throughput = self.parent._calculate_throughput(self.parent.current_pcap_file_path)
            deviation = abs(comparison_throughput - baseline_throughput)
            threshold_value = baseline_throughput * Decimal(threshold)
            if deviation > threshold_value:
                message = "Alert: Throughput anomaly detected."
                self.parent.logs.append(message)
            
    def generate_security_logs(self):
        baseline_ips, baseline_throughput = self.generate_baseline_values()
        security_events = self.Security_Events(self)
        security_events.detect_new_ip_addresses(baseline_ips)
        security_events.detect_throughput_anomaly(baseline_throughput)

        return self.logs

import os
from scapy.all import rdpcap, IP
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime
from collections import Counter

# Custom imports
from pdf_generator import PDFGenerator
from email_notifier import EmailNotifier

class PCAPAnalyzer:
    """Class to perform various analyses on PCAP files."""

    def __init__(self, pcap_path):
        """Load packets from a given PCAP file."""
        self.packets = rdpcap(pcap_path)

    def get_unique_ip_addresses(self):
        """Extracts unique IP addresses from packets."""
        return {packet[IP].src for packet in self.packets if IP in packet}.union(
            {packet[IP].dst for packet in self.packets if IP in packet})

    def calculate_throughput(self):
        """Calculates the throughput in kbps."""
        total_bytes = sum(len(packet) for packet in self.packets)
        duration = Decimal(self.packets[-1].time) - Decimal(self.packets[0].time)
        if duration == 0:  # Adding a check to prevent division by zero.
            return Decimal('0.000')
        throughput = (Decimal(total_bytes) * Decimal(8)) / (Decimal(1000) * duration)
        return throughput.quantize(Decimal('0.001'))
        


    def calculate_bandwidth(self):
        """Calculates bandwidth per second intervals and returns the max and min values in kbps."""
        bytes_per_second = []
        start_time = Decimal(self.packets[0].time)
        current_total = 0

        for packet in self.packets:
            packet_time = Decimal(packet.time)
            if packet_time - start_time >= 1:
                bytes_per_second.append(current_total)
                current_total = 0
                start_time = packet_time
            current_total += len(packet)
        
        bytes_per_second.append(current_total)  # Add the last interval
        kbps = [bytes * 8 / 1000 for bytes in bytes_per_second]
        return max(kbps), min(kbps)

class AnomalyDetector:
    """Class to detect anomalies based on throughput and IP addresses."""
    
    def __init__(self, baseline_data, comparison_data, threshold=0.1):
        self.baseline_data = baseline_data
        self.comparison_data = comparison_data
        self.threshold = Decimal(threshold)
        self.anomalies = []

    def check_new_ips(self):
        """Check for new IP addresses that weren't in the baseline data."""
        new_ips = self.comparison_data['ips'] - self.baseline_data['ips']
        if new_ips:
            self.anomalies.append(f"New IP addresses detected: {new_ips}")
        return new_ips

    def check_throughput_anomaly(self):
        """Check if the throughput has deviated beyond the threshold."""
        baseline_tp = self.baseline_data['throughput']
        comparison_tp = self.comparison_data['throughput']
        if abs(baseline_tp - comparison_tp) > baseline_tp * self.threshold:
            self.anomalies.append("Significant throughput anomaly detected.")

    def check_bandwidth_anomaly(self):
        """Check for significant changes in bandwidth usage."""
        baseline_max, baseline_min = map(Decimal, self.baseline_data['bandwidth'])
        comparison_max, comparison_min = map(Decimal, self.comparison_data['bandwidth'])

        max_threshold = baseline_max * self.threshold
        min_threshold = baseline_min * self.threshold

        if abs(baseline_max - comparison_max) > max_threshold or \
           abs(baseline_min - comparison_min) > min_threshold:
            self.anomalies.append("Bandwidth anomalies detected.")

class NetworkAnalysis:
    """Main class to manage network analysis and reporting."""

    def __init__(self, baseline_path, comparison_dir, notifier):
        self.baseline_analyzer = PCAPAnalyzer(baseline_path)
        self.comparison_dir = comparison_dir
        self.notifier = notifier
        self.baseline_path = baseline_path
        self.comparison_path = self.get_latest_comparison_file()

    def get_latest_comparison_file(self):
        """Fetch the latest PCAP file from the specified directory."""
        pcap_files = [os.path.join(self.comparison_dir, f) for f in os.listdir(self.comparison_dir) if f.endswith('.pcapng')]
        if not pcap_files:
            raise ValueError("No PCAP files found in the directory.")
        latest_file = max(pcap_files, key=os.path.getmtime)
        return latest_file
    
    def perform_analysis(self):
        """Perform analysis and handle notifications using the most recent comparison data."""
        self.comparison_analyzer = PCAPAnalyzer(self.get_latest_comparison_file())  
        baseline_data = {
            'ips': self.baseline_analyzer.get_unique_ip_addresses(),
            'throughput': self.baseline_analyzer.calculate_throughput(),
            'bandwidth': self.baseline_analyzer.calculate_bandwidth()
        }
        comparison_data = {
            'ips': self.comparison_analyzer.get_unique_ip_addresses(),
            'throughput': self.comparison_analyzer.calculate_throughput(),
            'bandwidth': self.comparison_analyzer.calculate_bandwidth()
        }
        self.detector = AnomalyDetector(baseline_data, comparison_data)  
        self.detector.check_new_ips()
        self.detector.check_throughput_anomaly()
        self.detector.check_bandwidth_anomaly()
    
        if self.detector.anomalies:
            self.report_anomalies(self.detector.anomalies)
            print("\n".join(self.detector.anomalies))
        else:
            print("No anomalies detected.")
    

    def report_anomalies(self, anomalies):
        if not anomalies:
            print("No anomalies to report.")
            return

        # Only attempt to send an email if a notifier is available
        if self.notifier:
            
            baseline_tp = self.baseline_analyzer.calculate_throughput()
            anomaly_tp = self.comparison_analyzer.calculate_throughput()
            baseline_band = self.baseline_analyzer.calculate_bandwidth()
            anomaly_band = self.comparison_analyzer.calculate_bandwidth()
            new_ips_detected = self.detector.check_new_ips()

            # Format values for PDF
            baseline_max_band, baseline_min_band = baseline_band
            anomaly_max_band, anomaly_min_band = anomaly_band

            # Generate PDF with all data
            pdf_report = PDFGenerator("anomaly_report.pdf")
            pdf_report.generate_pdf(
                baseline_tp=baseline_tp,
                anomaly_tp=anomaly_tp,
                baseline_max_band=baseline_max_band,
                baseline_min_band=baseline_min_band,
                anomaly_max_band=anomaly_max_band,
                anomaly_min_band=anomaly_min_band,
                new_ips=new_ips_detected
            )
            
            # Send email with the generated PDF
            self.notifier.send_email("Anomaly Report", "Please find the attached anomaly report.", "anomaly_report.pdf")
        else:
            print("Notifier is not configured. Skipping email notification.")

class DataProcessor:
    """Class to process PCAP data and provide statistics for web app visualization."""


    def __init__(self, comparison_dir, baseline_path, anomaly_detector=None):
        self.comparison_dir = comparison_dir
        self.baseline_path = baseline_path
        self.baseline_packets = None
        self.comparison_packets = None
        self.anomaly_detector = anomaly_detector
        self.load_packets()

    def set_pcap_path(self, comparison_path):
        """Set path for comparison pcap file and load packets for both baseline and comparison."""
        self.comparison_packets = rdpcap(comparison_path) if comparison_path else None
        self.baseline_packets = rdpcap(self.baseline_path) if self.baseline_path else None

    def load_packets(self):
        """Loads packets from both the baseline and comparison pcap files."""
        self.baseline_packets = rdpcap(self.baseline_path) if self.baseline_path else None
        self.comparison_packets = self.get_latest_comparison_file()


    def get_latest_comparison_file(self):
        """Fetch the latest PCAP file from the specified directory and load it."""
        pcap_files = [os.path.join(self.comparison_dir, f) for f in os.listdir(self.comparison_dir) if f.endswith('.pcapng')]
        if not pcap_files:
            raise ValueError("No PCAP files found in the directory.")
        latest_file_path = max(pcap_files, key=os.path.getmtime)
        return rdpcap(latest_file_path) if latest_file_path else None


    def calculate_throughput(self):
        """Calculates throughput in kbps for the loaded PCAP file."""
        if not self.packets:
            return 0
        total_bytes = sum(len(packet) for packet in self.packets)
        duration = max(packet.time for packet in self.packets) - min(packet.time for packet in self.packets)
        if duration == 0:
            return 0
        return (total_bytes * 8) / (duration * 1000)


    def calculate_throughput_per_minute(self, packets):
        """Calculates throughput in kbps and converts it to kbps per minute."""
        if not packets:
            return []
        throughput_results = []
        total_bytes = 0
        start_time = Decimal(packets[0].time)
        end_time = Decimal(packets[-1].time)
        duration_minutes = (end_time - start_time) / Decimal(60)
    
        for packet in packets:
            total_bytes += len(packet)
        
        if duration_minutes > 0:
            # Ensure total_bytes and other numeric literals are treated as Decimal
            throughput_kbps = (Decimal(total_bytes) * Decimal(8) / Decimal(1024)) / max(duration_minutes, Decimal(1))
            throughput_results.append(throughput_kbps)
    
        return throughput_results
    
    def get_throughputs(self):
        """Calculate and return throughput per minute for both baseline and comparison."""
        baseline_throughput = self.calculate_throughput_per_minute(self.baseline_packets)
        comparison_throughput = self.calculate_throughput_per_minute(self.comparison_packets)
        return baseline_throughput, comparison_throughput

    def get_security_logs(self):
        """Fetches all security logs based on anomalies detected."""
        if not self.anomaly_detector:
            return ["No anomaly detector linked", "Unable to fetch anomalies"]

        # Assuming anomaly_detector has a method or attribute that stores anomalies
        if not self.anomaly_detector.anomalies:
            return ["No anomalies detected"]

        # Format the output for clarity and usefulness
        return [f"Anomaly detected: {anomaly}" for anomaly in self.anomaly_detector.anomalies]
    
    def get_top_ips(self, packets):
        """Returns the top 5 IP addresses based on packet count."""
        ips = [packet[IP].src for packet in packets if IP in packet and packet[IP].src] + \
              [packet[IP].dst for packet in packets if IP in packet and packet[IP].dst]
        top_ips = Counter(ips).most_common(5)
        return [{'ip': ip, 'count': count} for ip, count in top_ips]

    def get_top_protocols(self, packets):
        """Returns the top 5 protocols used in the traffic."""
        protocols = [packet[IP].proto for packet in packets if IP in packet]
        protocol_names = {6: "TCP", 17: "UDP", 1: "ICMP"}
        protocol_counts = Counter(protocol_names.get(proto, f"Unknown ({proto})") for proto in protocols)
        return [{'protocol': protocol, 'count': count} for protocol, count in protocol_counts.most_common(5)]



# Example usage
if __name__ == "__main__":
    # Assuming these are your actual credentials and server details.
    # Make sure to secure your credentials and possibly use environment variables or a secure vault.
    email_notifier = EmailNotifier("NIDS_ana@hotmail.com", "158910FYP", "tahaseghayert.s@gmail.com", "smtp.office365.com", 587)


    # Ensure that the notifier is passed correctly here
    analysis = NetworkAnalysis(
        baseline_path=r'C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Packets\Full\1Order.pcapng',
        comparison_dir=r'C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Packets\Pi_packets',
        notifier=email_notifier  # Correctly pass the instantiated EmailNotifier
    )
    
    # Perform network analysis and handle notifications.
    analysis.perform_analysis()

    # DataProcessor now uses the same comparison directory and latest pcap file as NetworkAnalysis
    data_processor = DataProcessor(comparison_dir=r'C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Packets\Pi_packets',baseline_path=r'C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Packets\Full\1Order.pcapng',
                                 anomaly_detector= analysis.detector  )
    
    security_logs = data_processor.get_security_logs()
    print("Security Logs:", security_logs) # Example function call to calculate throughput




"""

This Python script is designed to analyze network traffic captured in PCAP files to detect
anomalies, focusing on throughput and new IP address appearances. The PCAPAnalyzer class 
extracts information from PCAP files, such as unique IP addresses and throughput. 
The AnomalyDetector class uses this information to identify deviations from baseline 
metrics that might indicate anomalous behavior. If anomalies are detected, it generates a
detailed report as a PDF document using the PDFGenerator class and sends this report via 
email using the EmailNotifier class. The main part of the script initializes these classes
with the necessary configuration, performs the analysis, and triggers report generation 
and email notification if anomalies are found. This automated process aids in monitoring 
network security by highlighting potential issues for further investigation.

"""

"""
*        ******************        *
████████╗ ██████╗ ████████╗███████╗
╚══██╔══╝██╔═══██╗╚══██╔══╝██╔════╝
   ██║   ██║   ██║   ██║   ███████╗
   ██║   ██║   ██║   ██║   ╚════██║
   ██║   ╚██████╔╝   ██║   ███████║
   ╚═╝    ╚═════╝    ╚═╝   ╚══════╝
*        ******************        * 
"""

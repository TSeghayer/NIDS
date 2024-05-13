import os
from scapy.all import rdpcap, IP
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime
from collections import Counter

# Custom imports for PDF generation and email notification functionalities.
from pdf_generator import PDFGenerator
from email_notifier import EmailNotifier

class PCAPAnalyzer:
    """
    This class is responsible for analyzing Packet Capture (PCAP) files to extract network data.
    It can calculate throughput, bandwidth, and list unique IP addresses involved in the traffic.
    """
    
    def __init__(self, pcap_path):
        """
        Initialize the PCAPAnalyzer with a specific PCAP file path.
        Loads the packets from the PCAP file into the 'packets' attribute.
        """
        self.packets = rdpcap(pcap_path)  # Load packets using Scapy's rdpcap function.

    def get_unique_ip_addresses(self):
        """
        Extracts unique IP addresses from the packets.
        Returns a set of unique source and destination IP addresses.
        """
        src_ips = {packet[IP].src for packet in self.packets if IP in packet}
        dst_ips = {packet[IP].dst for packet in self.packets if IP in packet}
        return src_ips.union(dst_ips)

    def calculate_throughput(self):
        """
        Calculates the average throughput of the network traffic in the PCAP file.
        Throughput is calculated as total bits transferred over total time, and it's returned in kilobits per second (kbps).
        Includes handling for zero-duration to avoid division by zero.
        """
        total_bytes = sum(len(packet) for packet in self.packets)
        start_time = Decimal(self.packets[0].time)
        end_time = Decimal(self.packets[-1].time)
        duration = end_time - start_time
        if duration == 0:
            return Decimal('0.000')
        throughput = (Decimal(total_bytes) * Decimal(8)) / (Decimal(1000) * duration)
        return throughput.quantize(Decimal('0.001'))  # Rounding to three decimal places.

    def calculate_bandwidth(self):
        """
        Calculates bandwidth utilization over time in kbps.
        Returns maximum and minimum bandwidth used during any second within the capture duration.
        """
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

        bytes_per_second.append(current_total)  # Accounting for the last interval.
        kbps = [bytes * 8 / 1000 for bytes in bytes_per_second]
        return max(kbps), min(kbps)

class AnomalyDetector:
    """
    Detects anomalies in network traffic by comparing new data against a baseline.
    Anomalies could be new IP addresses, significant throughput changes, or bandwidth fluctuations.
    """
    
    def __init__(self, baseline_data, comparison_data, threshold=0.1):
        """
        Initializes the detector with baseline data, comparison data, and a threshold for detecting anomalies.
        The threshold determines how significant a change must be to qualify as an anomaly.
        """
        self.baseline_data = baseline_data
        self.comparison_data = comparison_data
        self.threshold = Decimal(threshold)
        self.anomalies = []  # List to store detected anomalies.

    def check_new_ips(self):
        """
        Identifies new IP addresses in the comparison dataset that were not present in the baseline.
        Updates the anomalies list with any new IPs found.
        """
        new_ips = self.comparison_data['ips'] - self.baseline_data['ips']
        if new_ips:
            self.anomalies.append(f"New IP addresses detected: {new_ips}")
        return new_ips

    def check_throughput_anomaly(self):
        """
        Checks for significant deviations in throughput compared to the baseline.
        Anomalies are recorded if the change exceeds the defined threshold.
        """
        baseline_tp = self.baseline_data['throughput']
        comparison_tp = self.comparison_data['throughput']
        if abs(baseline_tp - comparison_tp) > baseline_tp * self.threshold:
            self.anomalies.append("Significant throughput anomaly detected.")

    def check_bandwidth_anomaly(self):
            """
            Checks for significant changes in bandwidth usage between the baseline and comparison data.
            Considers both maximum and minimum bandwidth values for anomaly detection.
            """
            baseline_max, baseline_min = self.baseline_data['bandwidth']
            comparison_max, comparison_min = self.comparison_data['bandwidth']
            max_change = abs(Decimal(baseline_max) - Decimal(comparison_max))
            min_change = abs(Decimal(baseline_min) - Decimal(comparison_min))
    
            # Ensure the threshold is a Decimal object
            threshold_decimal = Decimal(str(self.threshold))
    
            # Compare using Decimal types
            if max_change > Decimal(baseline_max) * threshold_decimal or min_change > Decimal(baseline_min) * threshold_decimal:
                self.anomalies.append("Bandwidth anomalies detected.")

class NetworkAnalysis:
    """
    Main class to manage network analysis and reporting.
    It uses PCAPAnalyzer to get network data and AnomalyDetector to find anomalies.
    Can notify via email if anomalies are detected using an EmailNotifier instance.
    """
    
    def __init__(self, baseline_path, comparison_dir, notifier):
        """
        Initializes network analysis with paths to baseline and comparison data, and an email notifier for alerts.
        """
        self.baseline_analyzer = PCAPAnalyzer(baseline_path)
        self.comparison_dir = comparison_dir
        self.notifier = notifier
        self.baseline_path = baseline_path
        self.comparison_path = self.get_latest_comparison_file()  # Dynamically fetches the latest comparison file.

    def get_latest_comparison_file(self):
        """
        Returns the path to the latest PCAP file in the comparison directory.
        Raises ValueError if no PCAP files are found.
        """
        pcap_files = [os.path.join(self.comparison_dir, f) for f in os.listdir(self.comparison_dir) if f.endswith('.pcapng')]
        if not pcap_files:
            raise ValueError("No PCAP files found in the directory.")
        latest_file = max(pcap_files, key=os.path.getmtime)
        return latest_file
    
    def perform_analysis(self):
        """
        Performs a comprehensive network analysis by comparing the latest data against the baseline.
        Detects anomalies and sends notifications if any are found.
        """
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
        """
        Generates a detailed report of detected anomalies and sends it via email.
        Includes throughput and bandwidth data, and lists new IP addresses.
        """
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
    """
    Class to process PCAP data and provide statistics for web app visualization.
    It loads packets from specified PCAP files, calculates throughput, and provides data
    about the most frequent IP addresses and protocols used in the network traffic.
    """

    def __init__(self, comparison_dir, baseline_path, anomaly_detector=None):
        """
        Initializes the DataProcessor with paths to the directory containing comparison PCAP files and
        a baseline PCAP file. Optionally includes an anomaly_detector to integrate with anomaly detection.
        Immediately loads packets from baseline and the latest comparison file.
        """
        self.comparison_dir = comparison_dir
        self.baseline_path = baseline_path
        self.baseline_packets = None
        self.comparison_packets = None
        self.anomaly_detector = anomaly_detector  # Optional anomaly detector for further analysis
        self.load_packets()  # Load packets upon initialization

    def set_pcap_path(self, comparison_path):
        """Updates the path for the comparison PCAP file and reloads the packets for both baseline and comparison."""
        self.comparison_packets = rdpcap(comparison_path) if comparison_path else None
        self.baseline_packets = rdpcap(self.baseline_path) if self.baseline_path else None

    def load_packets(self):
        """Loads packets from the baseline PCAP file and the latest comparison PCAP file available in the directory."""
        self.baseline_packets = rdpcap(self.baseline_path) if self.baseline_path else None
        self.comparison_packets = self.get_latest_comparison_file()

    def get_latest_comparison_file(self):
        """Identifies and loads the most recent PCAP file from the specified comparison directory."""
        pcap_files = [os.path.join(self.comparison_dir, f) for f in os.listdir(self.comparison_dir) if f.endswith('.pcapng')]
        if not pcap_files:
            raise ValueError("No PCAP files found in the directory.")
        latest_file_path = max(pcap_files, key=os.path.getmtime)
        return rdpcap(latest_file_path) if latest_file_path else None

    def calculate_throughput(self, packets):
        """Calculates the total throughput of the provided packets in kilobits per second (kbps)."""
        if not packets:
            return Decimal('0.000')
        total_bytes = sum(len(packet) for packet in packets)
        duration = Decimal(packets[-1].time) - Decimal(packets[0].time)
        if duration == 0:
            return Decimal('0.000')
        return (Decimal(total_bytes) * Decimal(8) / (Decimal(1000) * duration)).quantize(Decimal('0.001'))

    def calculate_throughput_over_time(self, packets):
        """Calculates throughput over time, returning results per minute."""
        if not packets:
            return [], []
        
        start_time = Decimal(packets[0].time)
        end_time = Decimal(packets[-1].time)
        interval = Decimal('60.0')  # 60 seconds
        current_time = start_time
        total_bytes = 0
        throughputs = []
        time_labels = []
    
        for packet in packets:
            if Decimal(packet.time) < current_time + interval:
                total_bytes += len(packet)
            else:
                throughput = (Decimal(total_bytes) * Decimal(8) / (Decimal(1000) * interval)).quantize(Decimal('0.001'))
                throughputs.append(float(throughput))
                time_labels.append(str(current_time))
                current_time += interval
                total_bytes = len(packet)  # Start counting next interval
    
        # Handle last interval if there's remaining data
        if total_bytes > 0:
            throughput = (Decimal(total_bytes) * Decimal(8) / (Decimal(1000) * (Decimal(packet.time) - current_time))).quantize(Decimal('0.001'))
            throughputs.append(float(throughput))
            time_labels.append(str(current_time))
    
        return time_labels, throughputs
    
    def get_throughput_data(self):
        """Returns the throughput for both baseline and comparison packets."""
        baseline_throughput = self.calculate_throughput(self.baseline_packets)
        comparison_throughput = self.calculate_throughput(self.comparison_packets)
        return baseline_throughput, comparison_throughput

    def get_security_logs(self):
        """Fetches all security logs based on anomalies detected by the linked anomaly detector."""
        if not self.anomaly_detector:
            return ["No anomaly detector linked", "Unable to fetch anomalies"]

        if not self.anomaly_detector.anomalies:
            return ["No anomalies detected"]

        return [f"Anomaly detected: {anomaly}" for anomaly in self.anomaly_detector.anomalies]
    
    def get_top_ips(self, packets):
        """Identifies and returns the top 5 IP addresses based on packet count from the provided packets."""
        ips = [packet[IP].src for packet in packets if IP in packet and packet[IP].src] + \
              [packet[IP].dst for packet in packets if IP in packet and packet[IP].dst]
        top_ips = Counter(ips).most_common(5)
        return [{'ip': ip, 'count': count} for ip, count in top_ips]

    def get_top_protocols(self, packets):
        """Identifies and returns the top 5 protocols based on usage in the provided packets."""
        protocols = [packet[IP].proto for packet in packets if IP in packet]
        protocol_names = {6: "TCP", 17: "UDP", 1: "ICMP"}  # Mapping of protocol numbers to names
        protocol_counts = Counter(protocol_names.get(proto, f"Unknown ({proto})") for proto in protocols)
        return [{'protocol': protocol, 'count': count} for protocol, count in protocol_counts.most_common(5)]





if __name__ == "__main__":
    # The condition checks if the script is being run as the main program and not imported as a module.

    # EmailNotifier is initialized with SMTP server details and credentials. 
    # It's essential to handle such sensitive information securely, possibly using environment variables
    # or a dedicated secrets management solution.
    email_notifier = EmailNotifier("NIDS_ana@hotmail.com", "158910FYP", "tahaseghayert.s@gmail.com", "smtp.office365.com", 587)

    # Initialize the NetworkAnalysis class with paths to the baseline and comparison PCAP files.
    # An EmailNotifier instance is passed to enable email notifications upon detecting network anomalies.
    analysis = NetworkAnalysis(
        baseline_path=r'C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Packets\Full\1Order.pcapng',
        comparison_dir=r'C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Packets\Pi_packets',
        notifier=email_notifier  # Pass the instantiated EmailNotifier to the analysis class.
    )
    
    # Perform the network analysis using the data specified. This method will load the PCAP files,
    # perform the comparisons, and check for any anomalies in network traffic.
    analysis.perform_analysis()

    # Instantiate the DataProcessor class using the same directories as the NetworkAnalysis.
    # It's passed an anomaly_detector, which is a reference to the detector used in the NetworkAnalysis.
    # This allows the DataProcessor to access detected anomalies for further processing or reporting.
    data_processor = DataProcessor(
        comparison_dir=r'C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Packets\Pi_packets',
        baseline_path=r'C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Packets\Full\1Order.pcapng',
        anomaly_detector=analysis.detector  # Passing the anomaly detector to link both analysis processes.
    )
    
    # Retrieve and print security logs, which include the details of detected anomalies.
    # The logs are fetched from the DataProcessor which uses its linked anomaly detector to access the anomaly data.
    security_logs = data_processor.get_security_logs()
    print("Security Logs:", security_logs)  # Output the security logs to the console.





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

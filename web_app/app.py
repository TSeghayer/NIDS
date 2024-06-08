from flask import Flask, render_template
from Anomaly import NetworkAnalysis, DataProcessor
from datetime import datetime 


app = Flask(__name__)

# Configuration for pcap files and baseline
PCAP_DIR = r"C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Packets\Pi_packets"
BASELINE_PCAP = r"C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Packets\Home_net\Baseline_home.pcapng"

# Initialize the classes
# The NetworkAnalysis instance is set up with paths to the baseline and comparison pcap directories.
# The notifier parameter is set to None, meaning no notifications (e.g., email alerts) will be sent.
network_analysis = NetworkAnalysis(baseline_path=BASELINE_PCAP, comparison_dir=PCAP_DIR, notifier=None)

# Perform analysis to initialize the anomaly detector
# This method call performs the initial analysis which is crucial for setting up the anomaly detection.
network_analysis.perform_analysis()

# Initialize DataProcessor with the anomaly detector from the analysis
# DataProcessor is used for processing network data to fetch various statistics and anomalies for visualization.
data_processor = DataProcessor(comparison_dir=PCAP_DIR, baseline_path=BASELINE_PCAP, anomaly_detector=network_analysis.detector)

def format_timestamps(timestamps):
    """Converts list of timestamps (assumed to be in seconds) into formatted date-time strings."""
    return [datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') for ts in timestamps]

@app.route('/')
def index():
    """
    The main page route that fetches and displays network analysis data.
    The data includes throughput, top IP addresses, top protocols, and any security logs related to anomalies.
    """

    # Retrieves top IPs and protocols from the comparison packets for visualization.
    top_ips = data_processor.get_top_ips(data_processor.comparison_packets)
    top_protocols = data_processor.get_top_protocols(data_processor.comparison_packets)

    # Gets security logs, which would include details of any detected anomalies.
    security_logs = data_processor.get_security_logs()

    # Fetches throughput for baseline and comparison from the DataProcessor.
    baseline_throughput, comparison_throughput = data_processor.get_throughput_data()

    # Get throughput over time data for both packet sets
    baseline_time_labels, baseline_throughput_series = data_processor.calculate_throughput_over_time(data_processor.baseline_packets)
    comparison_time_labels, comparison_throughput_series = data_processor.calculate_throughput_over_time(data_processor.comparison_packets)


    # Renders the Front1.html template, passing in all the fetched data for display on the webpage.
    return render_template(
        'Front1.html',
        top_ips=top_ips,
        top_protocols=top_protocols,
        security_logs=security_logs,
        baseline_throughput=baseline_throughput,
        comparison_throughput=comparison_throughput,
        time_labels=baseline_time_labels, 
        baseline_throughput_series=baseline_throughput_series,
        comparison_throughput_series=comparison_throughput_series
    )

@app.route('/about-us')
def about_us():
    """
    A simple route to display an 'About Us' page using the about_us.html template.
    """
    return render_template('about_us.html')

if __name__ == '__main__':
    # Starts the Flask application with debug mode enabled to facilitate development and troubleshooting.
    app.run(debug=True)



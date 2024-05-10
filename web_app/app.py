from flask import Flask, render_template, jsonify
from Anomaly import NetworkAnalysis, DataProcessor

app = Flask(__name__)

# Configuration for pcap files and baseline
PCAP_DIR = r"C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Packets\Pi_packets"
BASELINE_PCAP = r"C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Packets\Full\1Order.pcapng"

# Initialize the classes
network_analysis = NetworkAnalysis(baseline_path=BASELINE_PCAP, comparison_dir=PCAP_DIR, notifier=None)

# Perform analysis to initialize the anomaly detector
network_analysis.perform_analysis()

# Initialize DataProcessor with the anomaly detector from the analysis
data_processor = DataProcessor(comparison_dir=PCAP_DIR, baseline_path=BASELINE_PCAP, anomaly_detector=network_analysis.detector)

@app.route('/')
def index():
    # Get throughput data for baseline and comparison
    baseline_throughput, comparison_throughput = data_processor.get_throughputs()

    # Get other necessary data
    top_ips = data_processor.get_top_ips(data_processor.comparison_packets)
    top_protocols = data_processor.get_top_protocols(data_processor.comparison_packets)
    security_logs = data_processor.get_security_logs()
    #network_tp = data_processor.calculate_throughput()
    return render_template(
        'Front1.html',
        #throughput=network_tp,
        top_ips=top_ips,
        top_protocols=top_protocols,
        security_logs=security_logs,
        baseline_throughput=baseline_throughput,
        comparison_throughput=comparison_throughput
    )

@app.route('/about-us')
def about_us():
    return render_template('about_us.html')

if __name__ == '__main__':
    app.run(debug=True)


"""  IMPLEMNT UNITTESTING FOR TESTING AND VALIDATION """
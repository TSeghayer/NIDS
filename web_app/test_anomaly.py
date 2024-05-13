import unittest
from unittest.mock import patch
from decimal import Decimal
from Anomaly import PCAPAnalyzer, AnomalyDetector, NetworkAnalysis

class TestPCAPAnalyzer(unittest.TestCase):
    @patch('Anomaly.rdpcap')
    def test_get_unique_ip_addresses(self, mock_rdpcap):
        # Setup mock return value
        mock_rdpcap.return_value = [
            {'IP': {'src': '192.168.1.1', 'dst': '192.168.1.2'}},
            {'IP': {'src': '192.168.1.2', 'dst': '192.168.1.3'}}
        ]
        analyzer = PCAPAnalyzer(r'C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Packets\Pi_packets')
        expected_ips = {'192.168.1.1', '192.168.1.2', '192.168.1.3'}
        result = analyzer.get_unique_ip_addresses()
        self.assertEqual(result, expected_ips)

    @patch('Anomaly.rdpcap')
    def test_calculate_throughput(self, mock_rdpcap):
        # Setup for throughput calculation
        mock_rdpcap.return_value = [
            {'length': 100, 'time': Decimal('0.0')},
            {'length': 150, 'time': Decimal('10.0')}
        ]
        analyzer = PCAPAnalyzer(r'C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Packets\Pi_packets')
        result = analyzer.calculate_throughput()
        expected_throughput = Decimal('0.200')  # Example expected result calculation
        self.assertEqual(result, expected_throughput)

class TestAnomalyDetector(unittest.TestCase):
    def setUp(self):
        self.baseline_data = {'throughput': Decimal('100.0'), 'ips': {'192.168.1.1'}}
        self.comparison_data = {'throughput': Decimal('150.0'), 'ips': {'192.168.1.1', '192.168.1.2'}}
        self.detector = AnomalyDetector(self.baseline_data, self.comparison_data, Decimal('0.1'))

    def test_check_new_ips(self):
        result = self.detector.check_new_ips()
        self.assertIn('192.168.1.2', result)

    def test_check_throughput_anomaly(self):
        self.detector.check_throughput_anomaly()
        self.assertIn("Significant throughput anomaly detected.", self.detector.anomalies)

class TestNetworkAnalysis(unittest.TestCase):
    @patch('Anomaly.PCAPAnalyzer')
    @patch('Anomaly.EmailNotifier')
    def test_perform_analysis(self, MockEmailNotifier, MockPCAPAnalyzer):
        MockPCAPAnalyzer.return_value.calculate_throughput.return_value = Decimal('100.0')
        analysis = NetworkAnalysis(r'C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Packets\Pi_packets', r'C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Packets\Pi_packets', MockEmailNotifier())
        analysis.perform_analysis()
        self.assertIsInstance(analysis.detector, AnomalyDetector)

if __name__ == '__main__':
    unittest.main()

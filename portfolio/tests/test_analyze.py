import unittest
from analyze import auth_alerts, nmap_inventory, header_review

class AnalysisTests(unittest.TestCase):
    def test_auth_time_window_and_sources(self):
        data = "timestamp,source_ip,username,result\n2026-09-01T00:00:00Z,192.0.2.1,a,failure\n2026-09-01T00:05:00Z,192.0.2.1,b,failure\n2026-09-01T00:05:01Z,192.0.2.1,c,failure\n2026-09-01T00:05:02Z,192.0.2.2,a,failure"
        result = auth_alerts(data, 2, 5)
        self.assertEqual([x["failed_attempts"] for x in result], [2,2])
        self.assertEqual(result[-1]["users"], ["b","c"])
    def test_auth_out_of_order_and_success(self):
        data = "timestamp,source_ip,username,result\n2026-09-01T00:01:00Z,192.0.2.1,a,failure\n2026-09-01T00:00:00Z,192.0.2.1,a,failure\n2026-09-01T00:02:00Z,192.0.2.1,a,success"
        self.assertEqual(len(auth_alerts(data,2)),1)
    def test_invalid_timestamp(self):
        with self.assertRaises(ValueError):
            auth_alerts("timestamp,source_ip,username,result\nbad,192.0.2.1,a,failure")
    def test_naive_timestamp(self):
        with self.assertRaises(ValueError):
            auth_alerts("timestamp,source_ip,username,result\n2026-01-01T00:00:00,192.0.2.1,a,failure")
    def test_closed_ports_excluded(self):
        xml = '<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port><port protocol="tcp" portid="80"><state state="closed"/></port></ports></host></nmaprun>'
        result = nmap_inventory(xml)
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]["port"],22)
    def test_no_dtd(self):
        with self.assertRaises(ValueError):
            nmap_inventory('<!DOCTYPE nmaprun><nmaprun/>')
    def test_headers_case_and_colon(self):
        result = header_review('X-Content-Type-Options: nosniff\nContent-Security-Policy: default-src https://example.test')
        self.assertEqual(result[2]["status"], 'nosniff configured')
        self.assertIn('https://example.test',result[0]["values"][0])
        self.assertTrue(result[1]["status"].startswith('missing'))
    def test_duplicate_header(self):
        result = header_review('X-Content-Type-Options: nosniff\nx-content-type-options: invalid')
        self.assertEqual(result[2]["status"], 'unexpected or duplicate value')

if __name__ == '__main__': unittest.main()

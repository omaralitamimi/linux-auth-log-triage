import unittest
from main import triage


class LinuxLogTests(unittest.TestCase):
    def test_parses_failed_and_accepted(self):
        text = "sshd[1]: Failed password for invalid user admin from 192.0.2.8 port 22 ssh2\nsshd[2]: Accepted publickey for omar from 192.0.2.9 port 22 ssh2"
        result = triage(text)
        self.assertEqual(result["event_count"], 2)
        self.assertEqual(result["failed_by_ip"], {"192.0.2.8": 1})


if __name__ == "__main__":
    unittest.main()

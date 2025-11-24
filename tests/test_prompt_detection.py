import unittest
from mcp_ssh_session.session_manager import SSHSessionManager

class TestPromptDetection(unittest.TestCase):
    def setUp(self):
        self.manager = SSHSessionManager()

    def test_password_detection(self):
        # Should match
        self.assertEqual(self.manager._detect_awaiting_input("Please enter password: "), "password")
        self.assertEqual(self.manager._detect_awaiting_input("Password:"), "password")
        self.assertEqual(self.manager._detect_awaiting_input("user@host's password: "), "password")
        self.assertEqual(self.manager._detect_awaiting_input("[sudo] password for user:"), "password")
        
        # Should NOT match (false positives)
        self.assertIsNone(self.manager._detect_awaiting_input("password=secret\nDone."))
        self.assertIsNone(self.manager._detect_awaiting_input("Labels:\n - password: secret\n"))
        self.assertIsNone(self.manager._detect_awaiting_input("http://example.com?password=123"))
        self.assertIsNone(self.manager._detect_awaiting_input('"password": "value"')) # JSON
        self.assertIsNone(self.manager._detect_awaiting_input('var password="123"')) # Code
        self.assertIsNone(self.manager._detect_awaiting_input('password=secret')) # URL param at end

    def test_pager_detection(self):
        # Should match
        self.assertEqual(self.manager._detect_awaiting_input("lines\n(END)"), "pager")
        self.assertEqual(self.manager._detect_awaiting_input("lines\n:"), "pager")
        
        # Should NOT match
        self.assertIsNone(self.manager._detect_awaiting_input("(END)\nSome output"))
        self.assertIsNone(self.manager._detect_awaiting_input("The end of the file (END) is near")) 

    def test_press_key_detection(self):
        # Should match
        self.assertEqual(self.manager._detect_awaiting_input("Press any key to continue..."), "press_key")
        self.assertEqual(self.manager._detect_awaiting_input("Press Enter to continue"), "press_key")
        
        # Should NOT match
        self.assertIsNone(self.manager._detect_awaiting_input("1. Press any key to continue\n2. Next step"))

if __name__ == '__main__':
    unittest.main()
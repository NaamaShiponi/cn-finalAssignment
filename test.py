import unittest
import threading
import time
from client import main

from serverDHCP import get_available_ip

class TestSocketCommunication(unittest.TestCase):

    def test_DHCP(self):
        ip=get_available_ip()
        result = os.system("arping -c 1 " + ip)#if result == 0 The IP is already in use 
        self.assertNotEqual(result, 0)           

    def test_RUDP(self):
        main()
        len_origin_file=os.path.getsize('example.txt')
        len_After_RUDP_file=os.path.getsize('file_recv_rudp.html')
        self.assertEqual(len_origin_file, len_After_RUDP_file)


if __name__ == '__main__':
    unittest.main()
import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(__file__+"/../.."))
from trustrouter.packet import IPv6, ICMPv6_NDP_PrefixInfo, ICMPv6_NDP_RSASignature, ICMPv6_NDP_Option

class TestPacket(unittest.TestCase):
    RA_PACKET = b"\x60\x00\x00\x00\x01\xc8\x3a\xff\xfe\x80\x00\x00\x00\x00\x00\x00\x2c\xf2\x7e\xf7\x8f\x98\xdf\x97\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x86\x00\x46\xa8\x40\x00\x00\xb4\x00\x00\x00\x00\x00\x00\x00\x00\x03\x04\x40\xe0\x00\x01\x51\x80\x00\x00\x38\x40\x00\x00\x00\x00\x20\x01\x06\x38\x08\x07\x02\x1d\x00\x00\x00\x00\x00\x00\x00\x00\x19\x03\x00\x00\x00\x00\x00\x3c\x20\x01\x06\x38\x08\x07\x02\x01\x02\x11\x43\xff\xfe\x5b\x35\x1b\x01\x01\x00\x00\x1c\xd5\x06\x41\x0b\x18\x01\x00\x40\x7e\xd5\xfc\xc9\x69\x05\x3d\x8f\xa3\x7b\xb6\x09\x39\x86\xe2\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x30\x81\x9f\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x81\x8d\x00\x30\x81\x89\x02\x81\x81\x00\xaf\x96\x81\x88\xe2\xfb\x44\x20\x3d\xa9\xc9\x1b\x07\xde\x9d\x55\x27\x9e\xf7\xdc\xe6\xe2\xd2\x9b\x5c\x9a\x46\x72\x2b\x02\x10\xce\x4d\xc2\x87\xb7\x74\x03\x91\xac\xcd\xc5\x87\x5e\x06\xaf\xc8\x9a\xda\x29\xf9\xe9\x16\x8a\xc6\x97\x62\x76\xbb\x14\xb0\xab\xb7\xfe\x03\x34\x12\x98\x4b\x8e\x77\xba\x2b\x1b\x09\x8f\x6e\xd9\xb3\x59\x68\xb5\x35\xa8\x68\x08\x21\x70\x7f\x65\x6d\xca\xd1\x75\xdd\xc1\xbc\x1c\xc6\xee\x8b\x8c\x74\x3f\xbd\x8b\x8f\xde\x26\xa1\x99\x3b\xb2\x3c\xb6\x6b\xfc\xc5\xa1\x76\xaf\xd5\x07\x02\x62\x71\x6c\x09\x02\x03\x01\x00\x01\x00\x0d\x02\x00\x00\x00\x00\x00\x00\x00\x00\x4f\x17\xed\xe3\x79\xae\x2a\x02\x07\x00\x80\x81\x0a\x0b\x09\x00\x00\x00\x00\x00\x00\x00\x0c\x13\x00\x00\xf8\x55\x0b\xb2\x49\xe1\xd9\x0a\x2a\xe4\x00\xc2\x02\xc1\x8b\xff\x28\xcb\x82\x44\x51\x3c\x43\xd9\x54\xa3\xa3\x88\x03\xc5\x12\xf3\x00\x1f\x8c\x07\x55\x5b\x26\x35\xd6\xfb\x8b\x61\x69\xf2\x28\xb9\x33\x41\xa0\x01\xbb\x71\x37\x03\x02\x52\xb0\xe6\x54\x51\x0c\x50\x2b\xc0\x2a\x49\x11\x1f\x32\x0f\xfe\x0a\x53\x08\xf5\xf9\x10\x2d\x46\x86\x3d\x95\x89\xe2\x24\xc5\x76\x60\x13\x0b\x33\x4a\x1b\xc4\x5d\xef\xa7\x9e\xbf\x7f\x88\x32\xdf\x08\xba\x5b\xac\x52\xa3\xe3\x5f\xc1\x5a\xf0\x36\xfa\x76\x56\x4d\x7e\x80\x72\x39\xd0\x4c\x5f\xca\x24\x06\xa6\x12\x8f\x94\x2f\xe1\x67\xc4\xe6\xc3\xba\x4a\x03\x00\x00\x00\x00"

    def setUp(self):
        self.packet = IPv6(self.RA_PACKET)

    def testIPFields(self):
        self.assertEqual(self.packet["version"], 6)
        self.assertEqual(self.packet["traffic_class"], 0)
        self.assertEqual(self.packet["flow_label"], 0)
        self.assertEqual(self.packet["payload_length"], 456)
        self.assertEqual(self.packet["next_header"], 58)
        self.assertEqual(self.packet["hop_limit"], 255)

        self.assertEqual(self.packet["source_addr"], b"\xfe\x80\x00\x00\x00\x00\x00\x00\x2c\xf2\x7e\xf7\x8f\x98\xdf\x97")
        self.assertEqual(self.packet["destination_addr"], b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")

    def testRAFields(self):
        # Assuming the first ICMP message is a router advertisment
        ra_packet = self.packet.payload
        
        self.assertEqual(ra_packet["type"], 134)
        self.assertEqual(ra_packet["code"], 0)
        self.assertEqual(ra_packet["checksum"], 18088)
        self.assertEqual(ra_packet["hop_limit"], 64)
        self.assertEqual(ra_packet["managed"], 0)
        self.assertEqual(ra_packet["other"], 0)
        self.assertEqual(ra_packet["reserved"], 0)
        self.assertEqual(ra_packet["router_lifetime"], 180)
        self.assertEqual(ra_packet["reachable_timer"], 0)
        self.assertEqual(ra_packet["retrans_timer"], 0)

    def testPrefixOptionFields(self):
        # Assuming the first option is the prefix option
        prefix_option = self.packet.payload.options[0]

        self.assertIsInstance(prefix_option, ICMPv6_NDP_PrefixInfo)

        self.assertEqual(prefix_option["type"], 3)
        self.assertEqual(prefix_option["length"], 4)
        self.assertEqual(prefix_option["prefix_length"], 64)
        self.assertEqual(prefix_option["on_link"], 1)
        self.assertEqual(prefix_option["autonomous"], 1)
        
        # The reserved fields "MUST be initialized to zero by the sender
        # and MUST be ignored by the receiver.", so don't assume anything.
        #self.assertEqual(prefix_option["reserved1"], 0)
        #self.assertEqual(prefix_option["reserved2"], 0)
        
        self.assertEqual(prefix_option["valid_lifetime"], 86400)
        self.assertEqual(prefix_option["preferred_lifetime"], 14400)
        self.assertEqual(prefix_option["prefix"], b"\x20\x01\x06\x38\x08\x07\x02\x1d\x00\x00\x00\x00\x00\x00\x00\x00")

    def testSignatureOption(self):
        # Assuming seventh and last option: RSA Signature option
        sig_option = self.packet.payload.options[-1]
        self.assertIsInstance(sig_option, ICMPv6_NDP_RSASignature)
        
        self.assertEqual(sig_option["type"], 12)
        self.assertEqual(sig_option["length"], 19)
        self.assertEqual(sig_option["reserved"], 0)
        self.assertEqual(sig_option["key_hash"], b"\xf8\x55\x0b\xb2\x49\xe1\xd9\x0a\x2a\xe4\x00\xc2\x02\xc1\x8b\xff")
        self.assertEqual(sig_option["digital_signature"], b"\x28\xcb\x82\x44\x51\x3c\x43\xd9\x54\xa3\xa3\x88\x03\xc5\x12\xf3\x00\x1f\x8c\x07\x55\x5b\x26\x35\xd6\xfb\x8b\x61\x69\xf2\x28\xb9\x33\x41\xa0\x01\xbb\x71\x37\x03\x02\x52\xb0\xe6\x54\x51\x0c\x50\x2b\xc0\x2a\x49\x11\x1f\x32\x0f\xfe\x0a\x53\x08\xf5\xf9\x10\x2d\x46\x86\x3d\x95\x89\xe2\x24\xc5\x76\x60\x13\x0b\x33\x4a\x1b\xc4\x5d\xef\xa7\x9e\xbf\x7f\x88\x32\xdf\x08\xba\x5b\xac\x52\xa3\xe3\x5f\xc1\x5a\xf0\x36\xfa\x76\x56\x4d\x7e\x80\x72\x39\xd0\x4c\x5f\xca\x24\x06\xa6\x12\x8f\x94\x2f\xe1\x67\xc4\xe6\xc3\xba\x4a\x03\x00\x00\x00\x00")



    def testOtherOptions(self):
        # Assuming second option: Recursive DNS Server Option
        dns_option = self.packet.payload.options[1]
        self.assertIsInstance(dns_option, ICMPv6_NDP_Option)
        
        self.assertEqual(dns_option["type"], 25)
        self.assertEqual(dns_option["length"], 3)
        
        # Assuming third option: Source Link-layer Address
        src_option = self.packet.payload.options[2]
        self.assertIsInstance(src_option, ICMPv6_NDP_Option)
        
        self.assertEqual(src_option["type"], 1)
        self.assertEqual(src_option["length"], 1)

        # Assuming fourth option: CGA option
        cga_option = self.packet.payload.options[3]
        self.assertIsInstance(cga_option, ICMPv6_NDP_Option)
        
        self.assertEqual(cga_option["type"], 11)
        self.assertEqual(cga_option["length"], 24)

        # Assuming fifth option: Timestamp option
        timestamp_option = self.packet.payload.options[4]
        self.assertIsInstance(timestamp_option, ICMPv6_NDP_Option)
        
        self.assertEqual(timestamp_option["type"], 13)
        self.assertEqual(timestamp_option["length"], 2)

        # The sixth option is weird: type 42 is not defined...
        unknown_option = self.packet.payload.options[5]
        self.assertIsInstance(unknown_option, ICMPv6_NDP_Option)
        
        self.assertEqual(unknown_option["type"], 42)
        self.assertEqual(unknown_option["length"], 2)

if __name__ == '__main__':
    unittest.main()
        
        
        

        
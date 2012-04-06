import socket
import struct
import sys
import time
import win32file
from trustrouter.core import RAVerifier
from trustrouter.packet import IPPROTO_ICMPV6, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP
from ipaddr import IPv6Address

class WindowsAdapter(object):
    CALLOUT_DRIVER_NAME = "\\\\.\\trustrtr"
    POINTER_LENGTH = struct.calcsize("P")
    UNSIGNED_INTEGER_LENGTH = struct.calcsize("I")
    ACTION_BLOCK = "B"
    ACTION_PERMIT = "P"

    def __init__(self, shared_=None, log_fn=print):
        self.callout = win32file.CreateFile(
            self.CALLOUT_DRIVER_NAME,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            win32file.FILE_SHARE_READ,
            None,
            win32file.OPEN_EXISTING,
            0,
            0)
        self.log = log_fn
        if shared_ is None:
            self.shared = RAVerifier(self.log)
        else:
            self.shared = shared_
    
    def read_from_callout_until_success(self):
        result_code = 1
        while result_code != 0:
            try:
                result_code, result_buffer = win32file.ReadFile(
                    self.callout,
                    100000,
                    None)
            except Exception:
                #print("Tried ReadFile, got nothing.")
                pass

            time.sleep(1)

        return result_buffer

    def main(self):        
        result_buffer = self.read_from_callout_until_success()
        address_byte_array = bytearray(result_buffer[:self.POINTER_LENGTH])
        interface_index = bytearray(result_buffer[self.POINTER_LENGTH:self.POINTER_LENGTH + self.UNSIGNED_INTEGER_LENGTH])
        packet_byte_array = bytearray(result_buffer[(self.POINTER_LENGTH + self.UNSIGNED_INTEGER_LENGTH):])

        interface_index = struct.unpack("@I", interface_index)[0]

        #for packet_byte in packet_byte_array:
        #   print ("\\x%02x" % packet_byte, end="")

        result = bytearray()
        result.extend(address_byte_array)

        sock = socket.socket(
            socket.AF_INET6,
            socket.SOCK_RAW,
            IPPROTO_ICMPV6)        
        sock.settimeout(2)
        
        ''' 
            The CPAs will have the solicited-node multicast address as target.
            Therefore, we need to join this multicast group.
            On Mac OS X, this seems to happen automatically.
        '''
        self.join_multicast_group(sock, interface_index)
        
        if self.shared.verify(packet_byte_array, interface_index, sock):                
            action = self.ACTION_PERMIT
        else:
            action = self.ACTION_BLOCK
            
        sock.close()
        
        result.extend(struct.pack("c", bytes(action, encoding="ascii")))
        win32file.WriteFile(self.callout, result, None)
        
    def join_multicast_group(self, sock, interface_index):
        # Get all IPv6 address info tuples of the host.
        addr_info_list = [addr_info[4] for addr_info in socket.getaddrinfo(socket.gethostname(), None, family=socket.AF_INET6)]
        
        # Filter IPv6 address infos by the specified interface index, select only IPv6 address
        addr_list = [addr[0] for addr in addr_info_list if addr[3] == interface_index]

        for addr in addr_list:        
            # Removes the %-sign if present and everything thereafter.
            addr = addr.partition("%")[0]

            # Get the byte representation of the address
            addr_bytes = IPv6Address(addr).packed

            # Build the solicited-node multicast address by appending the
            # last 3 bytes of the unicast address to ff02::1:ff__:
            mcast_addr_end = addr_bytes[-3:]            
            mcast_addr = b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff" + mcast_addr_end
            mreq = struct.pack("=16sI", mcast_addr, interface_index)
            sock.setsockopt(IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, mreq)
        
def run(log_fn):
    adapter = WindowsAdapter(log_fn=log_fn)
    adapter.main()

import socket
import struct

import shared

class MacOSAdapter(object):

    KEXT_NAME = "net.trustrouter.kext"

    ACTION_REJECT = 1
    ACTION_ACCEPT = 0
    
    def __init__(self, socket_=None, shared_=None):
        if socket_ is None:
            self.socket = socket.socket(socket.PF_SYSTEM,
                                        socket.SOCK_STREAM,
                                        socket.SYSPROTO_CONTROL)
        else:
            self.socket = socket_
        
        if shared_ is None:
            self.shared = shared.Shared()
        else:
            self.shared = shared_
        

    def main(self):
        self.socket.connect(self.KEXT_NAME)
        while True:
            packet_id = self._readBytes(struct.calcsize("P"))
            # Read IPv6 Header (= 40 bytes)
            packet = self._readBytes(40)
            scopeid = self._remove_scope_id_from_addrs(packet)
            # Unmarshal payload length field
            payload_length = struct.unpack("!H", packet[4:6])[0]
            packet.extend(self._readBytes(payload_length))

            if self.shared.verify_ra(packet, scopeid):
                self._send_result(packet_id, self.ACTION_ACCEPT)
            else:
                self._send_result(packet_id, self.ACTION_ACCEPT)


    def _send_result(self, id, action):
        result = bytearray(id)
        result.extend(struct.pack("P", action))
        self.socket.send(result)


    def _readBytes(self, count):
        result = bytearray()
        while len(result) != count:
            result.extend(self.socket.recv(count - len(result)))
        return result


    def _remove_scope_id_from_addrs(self, ipv6header):
        scopeid = 0
        if self._is_link_local(ipv6header[8:10]):
            scopeid = struct.unpack("!H", ipv6header[10:12])[0]
            ipv6header[10:12] = b"\x00\x00"
        if self._is_link_local(ipv6header[24:26]):
            scopeid = struct.unpack("!H", ipv6header[26:28])[0]
            ipv6header[26:28] = b"\x00\x00"
        return scopeid


    def _is_link_local(self, addr):
        return (addr[0] == 0xfe and addr[1] & 0xc0 == 0x80) or \
               (addr[0] == 0xff and (addr[1] & 0x0f == 0x02 or
                                     addr[1] & 0x0f == 0x01))


def run():
    adapter = MacOSAdapter()
    adapter.main()
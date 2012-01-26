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
            self._clean_addresses(packet)
            # Unmarshal payload length field
            payload_length = struct.unpack("!H", packet[4:6])[0]
            packet.extend(self._readBytes(payload_length))

            reject_callback = self._get_callback(packet_id, self.ACTION_REJECT)
            accept_callback = self._get_callback(packet_id, self.ACTION_ACCEPT)

            self.shared.new_packet(packet, accept_callback, reject_callback)


    def _get_callback(self, id, action):
        def callback():
            result = bytearray(id)
            result.extend(struct.pack("P", action))
            self.socket.send(result)
        return callback


    def _readBytes(self, count):
        result = bytearray()
        while len(result) != count:
            result.extend(self.socket.recv(count - len(result)))
        return result


    def _clean_addresses(self, ipv6header):
        if ipv6header[8:10] == b"\xfe\x80":
            ipv6header[10:12] = b"\x00\x00"
        if ipv6header[24:26] == b"\xff\x02":
            ipv6header[26:28] = b"\x00\x00"        


if __name__ == "__main__":
    adapter = MacOSAdapter()
    adapter.main()
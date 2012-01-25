import struct

from packet import IPv6, ICMPv6_NDP_RSASignature
import security

# see RFC 3971
CGA_MESSAGE_TYPE_TAG = b"\x08\x6F\xCA\x5E\x10\xB2\x00\xC9\x9C\x8C\xE0\x01\x64\x27\x7C\x08"
CERT_PATH = './test/example_data/router0/router0.cer'

class Shared(object):

    def new_packet(self, data, accept_callback, reject_callback):
        packet = IPv6(data)
        icmp_data = bytearray(packet.payload.binary)

        rsa_option = None
        for option in packet.payload.options:
            if isinstance(option, ICMPv6_NDP_RSASignature):
                rsa_option = option
                break
            icmp_data.extend(option.binary)

        if rsa_option is None:
            print("Unsinged RA --> accept")
            accept_callback()
            return

        if rsa_option is not packet.payload.options[-1]:
            print("Found data after RSA option --> reject")
            reject_callback()
            return
        
        # recalculated checksum without RSA option before signature validation
        # see http://www.ietf.org/mail-archive/web/cga-ext/current/msg00327.html
        checksummed_data = self._pseudo_header(packet, len(icmp_data))
        # zero out old checksum
        icmp_data[2:4] = b"\x00\x00"
        checksummed_data.extend(icmp_data)
        icmp_data[2:4] = self._checksum(checksummed_data)

        signed_data = bytearray(CGA_MESSAGE_TYPE_TAG)
        signed_data.extend(packet["source_addr"])
        signed_data.extend(packet["destination_addr"])
        signed_data.extend(icmp_data)

        if security.verify_signature(CERT_PATH,
                                     signed_data,
                                     rsa_option["digital_signature"]):
            print("Valid signature --> accept")
            accept_callback()
        else:
            print("Invalid Signature --> reject")
            reject_callback()


    def _pseudo_header(self, packet, payload_length):
        pseudo_header = bytearray()
        pseudo_header.extend(packet["source_addr"])
        pseudo_header.extend(packet["destination_addr"])
        pseudo_header.extend(struct.pack("!IBBBB", payload_length, 0, 0, 0, 58))
        return pseudo_header


    def _checksum(self, binary):
        checksum = sum(struct.unpack("!%dH" % (len(binary) / 2), binary))
        while checksum >> 16:
            checksum = (checksum >> 16) + (checksum & 0xffff)
        return struct.pack("!H", ~checksum & 0xffff)

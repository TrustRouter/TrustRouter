import random
import socket
import struct
import time

from packet import IPv6, ICMPv6_NDP_RSASignature, IPPROTO_ICMPV6, ICMPv6_NDP_CPA, ICMPv6_NDP_Certificate, ICMPv6_NDP_PrefixInfo
import RAverification

# see RFC 3971
CGA_MESSAGE_TYPE_TAG = b"\x08\x6F\xCA\x5E\x10\xB2\x00\xC9\x9C\x8C\xE0\x01\x64\x27\x7C\x08"
#CA_PATH = '/Users/Mike/Desktop/MPRepro/TrustRouter/client/usermode/RAverification/test/example_data/only_one_block/ripe/ripe.cer'
CA_PATH = 'C:\\Users\\Thomas\\Uni\\SEND\\VMshare\\TrustRouter\\client\\usermode\\RAverification\\test\\example_data\\only_one_block\\ripe\\ripe.cer'
class Shared(object):

    def verify_router_advertisment(self, data, scopeid):
        packet = IPv6(data)
        icmp_data = bytearray(packet.payload.binary)

        rsa_option = None
        for option in packet.payload.options:
            if isinstance(option, ICMPv6_NDP_RSASignature):
                rsa_option = option
                break
            elif isinstance(option, ICMPv6_NDP_PrefixInfo):
                # Todo: more than one prefix option
                prefix_option = option
            icmp_data.extend(option.binary)

        if rsa_option is None:
            print("Unsigned RA --> accept")
            return True

        if rsa_option is not packet.payload.options[-1]:
            print("Found data after RSA option --> reject")
            return False

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

        # send CPS
        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, IPPROTO_ICMPV6)
        identifier = random.randint(0, (2 ** 16) - 1)
        cps = struct.pack("!BBHHH", 148, 0, 0, identifier, 65535)
        # send to all routers multicast address
        # addr = ("ff02::2", 0, 0, scopeid)
        # NDProtector has a bug when sending to all routers mutlicast, using unicast instead
        addr = (self._ipv6_n_to_a(packet["source_addr"]), 0, 0, scopeid)
        sock.sendto(cps, addr)
        sock.settimeout(2)

        # receive CPAs
        intermediate_certs = []
        router_certs = []

        starttime = time.time()

        while time.time() - starttime < 15:
            try:
                cpa_data, from_addr = sock.recvfrom(65535)
            except socket.timeout:
                print("Timeout")
                continue

            if from_addr[3] != scopeid or cpa_data[0] != 149:
                continue
            cpa = ICMPv6_NDP_CPA(cpa_data)
            if cpa["identifier"] != identifier and cpa["identifier"] != 0:
                continue
            print(cpa["component"])
            
            for cert_option in cpa.options:
                sdg = open("./comp" + str(cpa["component"]), "wb")
                sdg.write(cert_option["certificate"])
                sdg.close()
                if isinstance(cert_option, ICMPv6_NDP_Certificate):
                    cert = self._remove_padding(cert_option["certificate"])
                    if cpa["component"] != 0:
                        intermediate_certs.append(cert)
                    else:
                        router_certs.append(cert)
                    # TODO: more than one certificate option
                    break
            for router_cert in router_certs:
                print("Cert found")
                if self._verify(intermediate_certs,
                                router_cert,
                                prefix_option,
                                signed_data,
                                rsa_option):
                    print("Valid signature --> accept")
                    return True
        print("Invalid Signature --> reject")
        return False

    def _ipv6_n_to_a(self, address):
        # Needed to convert router's IP address (normally we would send to router multicast address)
        return "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x" % tuple(address)
    
    def _verify(self, intermediate_certs, router_cert, prefix_option, signed_data, rsa_option):
        result1 =  RAverification.verify_prefix_with_cert(
                    CA_PATH,
                    intermediate_certs,
                    router_cert, prefix_option["prefix"],
                    prefix_option["prefix_length"]
                )
        result2 = RAverification.verify_signature(
                    router_cert,
                    signed_data,
                    rsa_option["digital_signature"]
                )
        print("Result 1 ", result1)
        print("Result 2 ", result2)

        return result1 and result2 


    def _remove_padding(self, data):
        for i in range(len(data) - 1, -1, -1):
            if data[i] != 0:
                return data[:i+1]


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

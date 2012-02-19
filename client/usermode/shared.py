import random
import socket
import struct
import time

import packet
import security
import trust_anchors

# see RFC 3971
CGA_MESSAGE_TYPE_TAG = b"\x08\x6F\xCA\x5E\x10\xB2\x00\xC9\x9C\x8C\xE0\x01\x64\x27\x7C\x08"

class Shared(object):

    def __init__(self):
        self.trust_anchors = security.CertificateStack()
        for anchor in trust_anchors.certificates:
            self.trust_anchors.add(anchor)

    def verify_ra(self, data, scopeid):
        ra = packet.IPv6(data)
        rsa_option, prefix_options, icmp_data = self._extract_info(ra)

        if rsa_option is None:
            print("Unsigned RA --> accept")
            return True

        if rsa_option is not ra.payload.options[-1]:
            print("Found data after RSA option --> reject")
            return False
        
        if len(prefix_options) != 1:
            # TODO: how to handle multiple prefixes and no prefixes?
            return False
        prefix_option = prefix_options[0]

        prefix = "IPv6:%s/%d" % (
            self._print_ipv6_addr(prefix_option["prefix"]),
            prefix_option["prefix_length"]
        )
        signed_data = self._get_signed_data(ra, icmp_data)
        signature = rsa_option["digital_signature"]

        sock = socket.socket(socket.AF_INET6,
                             socket.SOCK_RAW,
                             packet.IPPROTO_ICMPV6)        
        identifier = self._send_cps(sock, scopeid, ra["source_addr"])

        # process CPAs
        intermediate_certs = security.CertificateStack()
        router_certs = []

        sock.settimeout(2)
        starttime = time.time()

        while time.time() - starttime < 15:
            cpa = self._receive_cpa(sock, scopeid, identifier)
            if cpa is None:
                continue
            
            self._extract_cert_options(cpa, intermediate_certs, router_certs)

            for cert in router_certs:
                chain = cert.get_chain(self.trust_anchors, intermediate_certs)
                if chain is None:
                    continue
                if not chain.verify_prefix(prefix):
                    continue
                if cert.verify_signature(signed_data, signature):
                    print("Valid signature --> accept")
                    return True
                
        print("Invalid Signature --> reject")
        sock.close()
        return False


    def _extract_info(self, ra):
        icmp_data = bytearray(ra.payload.binary)
        rsa_option = None
        prefix_options = []
        for option in ra.payload.options:
            if isinstance(option, packet.ICMPv6_NDP_RSASignature):
                rsa_option = option
                break
            elif isinstance(option, packet.ICMPv6_NDP_PrefixInfo):
                prefix_options.append(option)
            icmp_data.extend(option.binary)
        
        return rsa_option, prefix_options, icmp_data


    def _get_signed_data(self, ra, icmp_data):
        # recalculated checksum without RSA option before signature validation
        # see http://www.ietf.org/mail-archive/web/cga-ext/current/msg00327.html
        checksummed_data = self._pseudo_header(ra, len(icmp_data))         
        # zero out old checksum
        icmp_data[2:4] = b"\x00\x00"
        checksummed_data.extend(icmp_data)
        icmp_data[2:4] = self._checksum(checksummed_data)
        
        signed_data = bytearray(CGA_MESSAGE_TYPE_TAG)
        signed_data.extend(ra["source_addr"])
        signed_data.extend(ra["destination_addr"])
        signed_data.extend(icmp_data)
        return signed_data


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
    

    def _send_cps(self, sock, scopeid, address):
        identifier = random.randint(0, (2 ** 16) - 1)
        cps = struct.pack("!BBHHH", 148, 0, 0, identifier, 65535)
        # send to all routers multicast address
        # addr = ("ff02::2", 0, 0, scopeid)
        # NDProtector bug when sending to mutlicast addr, use unicast instead
        addr = self._print_ipv6_addr(address), 0, 0, scopeid
        sock.sendto(cps, addr)
        return identifier


    def _receive_cpa(self, sock, scopeid, identifier):
        try:
            cpa_data, from_addr = sock.recvfrom(65535)
        except socket.timeout:
            print("Timeout")
            return None

        if from_addr[3] != scopeid or cpa_data[0] != 149:
            return None
        
        cpa = packet.ICMPv6_NDP_CPA(cpa_data)
        if cpa["identifier"] != identifier and cpa["identifier"] != 0:
            return None
        
        print(cpa["component"])
        return cpa
    

    def _extract_cert_options(self, cpa, intermediate_certs, router_certs):
        for cert_option in cpa.options:
            if isinstance(cert_option, packet.ICMPv6_NDP_Certificate):
                if cpa["component"] != 0:
                    intermediate_certs.add(cert_option["certificate"])
                else:
                    cert = security.Certificate(cert_option["certificate"])
                    router_certs.append(cert)
                # TODO: more than one certificate option
                break


    def _print_ipv6_addr(self, address):
        return "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x" % tuple(address)
            
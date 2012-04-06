import random
import socket
import struct
import time

from trustrouter import config
from trustrouter import packet
from trustrouter import security
from trustrouter import certificates

# see RFC 3971, section 5.2, "Digital Signature"
CGA_MESSAGE_TYPE_TAG = b"\x08\x6F\xCA\x5E\x10\xB2\x00\xC9\x9C\x8C\xE0\x01\x64\x27\x7C\x08"

# Maximum time the certificate retrieval process may last, in seconds.
# See RFC 3971, section 10.1 Constants:
CPS_RETRY_MAX = 15

class RAVerifier(object):

    def __init__(self, log_fn=print, user_config=None):
        self.log = log_fn
        self.config = config.Config(user_config, self.log)
        # add trust anchors that ship with TrustRouter
        self.config.trust_anchors.extend(certificates.trust_anchors)

        self._trusted_routers = []
        self._secured_prefixes = []

    def verify(self, data, scopeid, sock):
        if self.config.mode == config.MODE_NO_SEND:
            return True

        ra = packet.IPv6(data)
        rsa_option, prefix_options, icmp_data = self._extract_info(ra)

        if len(prefix_options) != 1:
            # TODO: how to handle multiple prefixes and no prefixes?
            self.log("Not exactly one prefix option --> reject")
            return False
        prefix_option = prefix_options[0]

        if rsa_option is None:
            result = self._accept_unsigned_ra(ra, prefix_option)
            self.log("Unsigned RA --> Accepted: %s" % result)
            return result

        if rsa_option is not ra.payload.options[-1]:
            self.log("Found data after RSA option --> reject")
            return False

        signed_data = self._get_signed_data(ra, icmp_data)

        if not self.config.ndprotector_compatibility:
            # send cps to all routers multicast address
            cps_addr = ("ff02::2", 0, 0, scopeid)
            # set hop limit to 255 (10 = IPV6_MULTICAST_HOPS)
            sock.setsockopt(packet.IPPROTO_IPV6, 10, 255)
        else:
            # NDProtector has a bug when sending to all routers mutlicast, using unicast instead
            cps_addr = (self._ipv6_n_to_a(ra["source_addr"]), 0, 0, scopeid)
            # set hop limit to 255 (4 = IPV6_UNICAST_HOPS)
            sock.setsockopt(packet.IPPROTO_IPV6, 4, 255)
        identifier = self._send_cps(sock, cps_addr)

        # process CPAs
        intermediate_certs = []
        router_certs = []        
        starttime = time.time()

        while time.time() - starttime < CPS_RETRY_MAX:
            cpa = self._receive_cpa(sock, scopeid, identifier)
            
            if cpa is None:
                continue
            
            self._process_cert_options(cpa, intermediate_certs, router_certs)

            if self._verify(router_certs,
                            intermediate_certs,
                            prefix_option,
                            signed_data,
                            rsa_option["digital_signature"]):
                self.log("Valid signature --> accept")
                self._add_to_secured_list(ra, prefix_option)
                return True
                
        self.log("Invalid Signature --> reject")
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
    

    def _send_cps(self, sock, address):
        self.log("request certificates")
        identifier = random.randint(0, (2 ** 16) - 1)
        cps = struct.pack("!BBHHH", 148, 0, 0, identifier, 65535)
        sock.sendto(cps, address)
        return identifier


    def _receive_cpa(self, sock, scopeid, identifier):
        try:
            cpa_data, from_addr = sock.recvfrom(65535)
        except socket.timeout:
            self.log("CPA receive timeout")
            return None
        if from_addr[3] != scopeid or cpa_data[0] != 149:
            return None
        
        cpa = packet.ICMPv6_NDP_CPA(cpa_data)
        if cpa["identifier"] != identifier and cpa["identifier"] != 0:
            return None
        self.log("received CPA after")
        return cpa
    

    def _process_cert_options(self, cpa, intermediate_certs, router_certs):
        for cert_option in cpa.options:
            if isinstance(cert_option, packet.ICMPv6_NDP_Certificate):
                if cpa["component"] != 0:
                    intermediate_certs.append(cert_option["certificate"])
                else:
                    router_certs.append(cert_option["certificate"])
                # TODO: more than one certificate option
                break

    
    def _verify(self, router_certs, intermediate_certs,
                prefix_option, signed_data, signature):
        for router_cert in router_certs:                
            if not security.verify_prefix_with_cert(
                    self.config.trust_anchors,
                    intermediate_certs,
                    router_cert, prefix_option["prefix"],
                    prefix_option["prefix_length"]):
                continue            
            
            if security.verify_signature(
                    router_cert,
                    signed_data,
                    signature):
                return True
        
        return False


    def _ipv6_n_to_a(self, address):
        # Needed to convert router's IP address (normally we would send to router multicast address)
        return "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x" % tuple(address)


    def _accept_unsigned_ra(self, ra, prefix_option):
        if (self.config.mode == config.MODE_ONLY_SEND or
                (self.config.mode == config.MODE_NO_UNSECURED_AFTER_SECURED and
                    len(self._trusted_routers) > 0)):
            return False
        # mixed mode
        prefix = (prefix_option["prefix"], prefix_option["prefix_length"])
        return (ra["source_addr"] not in self._trusted_routers and 
                prefix not in self._secured_prefixes)


    def _add_to_secured_list(self, ra, prefix_option):
        if ra["source_addr"] not in self._trusted_routers:
            self._trusted_routers.append(ra["source_addr"])
        prefix = (prefix_option["prefix"], prefix_option["prefix_length"])
        if prefix not in self._secured_prefixes:
            self._secured_prefixes.append(prefix)

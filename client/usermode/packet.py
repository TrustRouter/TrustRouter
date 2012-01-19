import math
import struct
import socket
from collections import OrderedDict

ICMPv6_TYPES = {
    134 : "ICMPv6_NDP_RA"
}

ICMPv6_NDP_OPTIONS = {
    3 : "ICMPv6_NDP_PrefixInfo",
    12 : "ICMPv6_NDP_RSASignature"
}

class AbstractPacket(object):
    def parse(self, binary):
        bit_offset = 0
        for name, field in self.fields.items():
            binary, bit_offset = field.parse(binary, bit_offset)
        return binary

    def __getitem__(self, key):
        return self.fields[key].value


class IPv6(AbstractPacket):
    def __init__(self, binary):
        self.fields = OrderedDict([
            ("version", BitField(4)),
            ("traffic_class", BitField(8)),
            ("flow_label", BitField(20)),
            ("payload_length", BitField(16)),
            ("next_header", BitField(8)),
            ("hop_limit", BitField(8)),
            ("source_addr", ByteField(16)),
            ("destination_addr", ByteField(16))
        ])
        remaining_binary = self.parse(binary)
        self.binary = binary[:len(binary) - len(remaining_binary)]
        # ToDo: Parse IPv6 Extensions
        self.parse_payload(remaining_binary)
          
        
    def get_payload_class(self, binary):
        next_header = self["next_header"]
        if next_header == socket.IPPROTO_ICMPV6:
            icmp_type = binary[0]
            try:
                return globals()[ICMPv6_TYPES[icmp_type]]
            except KeyError:
                raise Exception("unsupported ICMPv6 type") 
        else:
            raise Exception("only ICMPv6 supported") 

    def parse_payload(self, binary):
        cls = self.get_payload_class(binary)
        self.payload = cls(binary)


class ICMPv6_NDP_RA(AbstractPacket):
    def __init__(self, binary):
        self.fields = OrderedDict([
            ("type", BitField(8)),
            ("code", BitField(8)),
            ("checksum", BitField(16)),
            ("hop_limit", BitField(8)),
            ("managed", BitField(1)),
            ("other", BitField(1)),
            ("reserved", BitField(6)),
            ("router_lifetime", BitField(16)),
            ("reachable_timer", BitField(32)),
            ("retrans_timer", BitField(32))
        ])
        self.options = []
        remaining_binary = self.parse(binary)
        self.binary = binary[:len(binary) - len(remaining_binary)]
        self.parse_options(remaining_binary)

    
    def parse_options(self, binary):
        while binary:
            cls = self.get_option_class(binary)
            option = cls(binary)
            binary = binary[len(option.binary):]
            self.options.append(option)
            
    
    def get_option_class(self, binary):
        option_type = binary[0]
        try:
            class_name = ICMPv6_NDP_OPTIONS.get(option_type, "ICMPv6_NDP_Option") 
            return globals()[class_name]
        except KeyError:
            raise Exception("unsupported ICMPv6 NDP option: %d" % option_type)
            
            
class ICMPv6_NDP_PrefixInfo(AbstractPacket):
    def __init__(self, binary):
        self.fields = OrderedDict([
            ("type", BitField(8)),
            ("length", BitField(8)),
            ("prefix_length", BitField(8)),
            ("on_link", BitField(1)),
            ("autonomous", BitField(1)),
            ("reserved1", BitField(6)),
            ("valid_lifetime", BitField(32)),
            ("preferred_lifetime", BitField(32)),
            ("reserved2", BitField(32)),
            ("prefix", ByteField(16))
        ])
        remaining_binary = self.parse(binary)
        self.binary = binary[:len(binary) - len(remaining_binary)]


class ICMPv6_NDP_RSASignature(AbstractPacket):
    def __init__(self, binary):
        self.fields = OrderedDict([
            ("type", BitField(8)),
            ("length", BitField(8)),
            ("reserved", BitField(16)),
            ("key_hash", ByteField(16)),
            ("digital_signature", VarByteField(self._sig_len)),
        ])
        remaining_binary = self.parse(binary)
        self.binary = binary[:len(binary) - len(remaining_binary)]

    def _sig_len(self):
        return (self["length"] * 8 - 20)


class ICMPv6_NDP_Option(AbstractPacket):
    def __init__(self, binary):
        self.fields = OrderedDict([
            ("type", BitField(8)),
            ("length", BitField(8)),
        ])
        remaining_binary = self.parse(binary)
        self.binary = binary[:len(binary) - len(remaining_binary)]

    def parse(self, binary):
        binary = super(ICMPv6_NDP_Option, self).parse(binary)
        bytes_done = self["length"] * 8 - 2
        return binary[bytes_done:]


class BitField(object):
    def __init__(self, len):
        self.len = len

    def parse(self, binary, bit_offset):
        needed_bytes = math.ceil((self.len + bit_offset) / 8)
        bytes = binary[:needed_bytes]
        unpacked = struct.unpack("!%dB" % needed_bytes, bytes)

        result = 0
        for byte in unpacked:
            result = result << 8
            result = result | byte
        
        # remove high bits
        result = result & ((1 << (needed_bytes * 8 - bit_offset)) - 1)
        # remove lower bits
        result = result >> (needed_bytes * 8 - self.len - bit_offset)

        self.value = result

        done_bytes = (bit_offset + self.len) // 8
        bit_offset = (bit_offset + self.len) % 8
        return binary[done_bytes:], bit_offset


class ByteField(object):
    def __init__(self, len):
        self.len = len
    
    def parse(self, binary, bit_offset):
        if bit_offset != 0:
            raise Exception("ByteField must be byte-aligned")
        self.value = binary[:self.len]
        return binary[self.len:], 0


class VarByteField(ByteField):
    def __init__(self, len_fn):
        self.len_fn = len_fn

    def parse(self, binary, bit_offset):
        self.len = self.len_fn()
        return super(VarByteField, self).parse(binary, bit_offset)

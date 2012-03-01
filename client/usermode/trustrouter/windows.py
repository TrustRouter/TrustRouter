import win32file
import sys
import struct
import time
from trustrouter.core import RAVerifier

class WindowsAdapter(object):
    CALLOUT_DRIVER_NAME = "\\\\.\\SendCallout"
    POINTER_LENGTH = struct.calcsize("P")
    UNSIGNED_INTEGER_LENGTH = struct.calcsize("I")
    ACTION_BLOCK = "B"
    ACTION_PERMIT = "P"

    def __init__(self, shared_=None):
        self.callout = win32file.CreateFile(
            self.CALLOUT_DRIVER_NAME,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            win32file.FILE_SHARE_READ,
            None,
            win32file.OPEN_EXISTING,
            0,
            0)
        if shared_ is None:
            self.shared = RAVerifier()
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
                print("Tried ReadFile, got nothing.")
                pass

            time.sleep(1)

        return result_buffer

    def main(self):        
        while True:
            result_buffer = self.read_from_callout_until_success()
            address_byte_array = bytearray(result_buffer[:self.POINTER_LENGTH])
            interface_index = bytearray(result_buffer[self.POINTER_LENGTH:self.POINTER_LENGTH + self.UNSIGNED_INTEGER_LENGTH])
            packet_byte_array = bytearray(result_buffer[(self.POINTER_LENGTH + self.UNSIGNED_INTEGER_LENGTH):])

            interface_index = struct.unpack("@I", interface_index)[0]

            #for packet_byte in packet_byte_array:
            #   print ("\\x%02x" % packet_byte, end="")

            result = bytearray()
            result.extend(address_byte_array)

            if self.shared.verify(packet_byte_array, interface_index):                
                action = self.ACTION_PERMIT
            else:
                action = self.ACTION_BLOCK
                
            result.extend(struct.pack("c", bytes(action, encoding="ascii")))
            win32file.WriteFile(self.callout, result, None)


if __name__ == "__main__":
    adapter = WindowsAdapter()
    adapter.main()

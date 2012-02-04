import win32file
import sys
import struct
import time
import shared

class WindowsAdapter(object):
    CALLOUT_DRIVER_NAME = "\\\\.\\SendCallout"
    POINTER_LENGTH = struct.calcsize("P")
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
            self.shared = shared.Shared()
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

            time.sleep(10)

        return result_buffer

    def main(self):        
        while True:
            result_buffer = self.read_from_callout_until_success()
            address_byte_array = bytearray(result_buffer[:self.POINTER_LENGTH])
            packet_byte_array = bytearray(result_buffer[self.POINTER_LENGTH:])

            for packet_byte in packet_byte_array:
                print ("\\x%02x" % packet_byte, end="")

            reject_callback = self._get_callback(address_byte_array, self.ACTION_BLOCK)
            accept_callback = self._get_callback(address_byte_array, self.ACTION_PERMIT)

            self.shared.new_packet(packet_byte_array, accept_callback, reject_callback)


    def _get_callback(self, address_byte_array, action):
        def callback():
            result = bytearray()
            result.extend(address_byte_array)
            result.extend(struct.pack("c", bytes(action, encoding="ascii")));

            win32file.WriteFile(self.callout, result, None)
        return callback


if __name__ == "__main__":
    adapter = WindowsAdapter()
    adapter.main()

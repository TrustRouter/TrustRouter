import win32file, sys

hdevice = win32file.CreateFile("\\\\.\\SendCallout", win32file.GENERIC_READ | win32file.GENERIC_WRITE, win32file.FILE_SHARE_READ, None, win32file.OPEN_EXISTING, 0, 0)
(resultCode, resultBuffer) = win32file.ReadFile(hdevice, 100000, None)

for i in range(len(resultBuffer)):
    b = resultBuffer[i]
    print (hex(b), "\t", end="")
        
if len(sys.argv) > 1:
	actionString = sys.argv[1]
else:
	actionString = "Block"
		
result = win32file.WriteFile(hdevice, bytearray(actionString, encoding="ascii"), None)
print (result)
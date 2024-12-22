import hashlib

data = open("3", 'rb').read()

check = data[-0x40:]
val = hashlib.sha256(data[0:-0x40]).digest()

print("file %s\ncalc %s" % (check,val.hex()))

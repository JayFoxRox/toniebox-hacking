#!/usr/bin/env python3

print("DO NOT USE THIS! UNTESTED AND STUBBED HACKS. YOUR TONIEBOX WILL BE BRICKED!")

import struct
import hashlib
import sys
from datetime import datetime

path = sys.argv[1]

image = open(path, 'rb').read()

def write(o, data):
  global image
  image = image[0:o] + data + image[o+len(data):]
  
def read(o, length):
  global image
  return image[o:o+length]

def read8(o):
  return struct.unpack("<B", read(o, 1))[0]

def write8(o, v):
  write(o, struct.pack("<B", v))

def read16(o):
  return struct.unpack("<H", read(o, 2))[0]

def write16(o, v):
  write(o, struct.pack("<H", v))

def read16b(o):
  return struct.unpack(">H", read(o, 2))[0]

def write16b(o, v):
  write(o, struct.pack(">H", v))

def read32(o):
  return struct.unpack("<I", read(o, 4))[0]

def write32(o, v):
  write(o, struct.pack("<I", v))

def dump_seg(o):
  load = read32(o+0)
  length = read32(o+4)
  print("file 0x%X load 0x%X len 0x%X" % (o, load, length))
  return load,length,o + length + 0x8

# Attach some custom segment for hacked IROM stuff
#FIXME: Mark the segment as hacked, so we don't accidentally patch twice
def write_seg(o, load, length):
  write32(o+0, load)
  write32(o+4, length)
  return o + length + 0x8

# Search for things which end up in ESP32S3 IROM
irom_start = 0x42000000
irom_end =   0x43FFFFFF

iram1_start = 0x3FC88000
iram1_end = 0x3FCEFFFF 


# Check ESP32S3 magic
assert(read8(0) == 0xE9)

def readCString(offset, length):
  data = read(offset, length)
  s, _, zeroes = data.partition(b'\x00')
  assert(x == 0x00 for x in zeroes)
  return s

ep = read32(4)
print("entry-point: 0x%X" % ep)

unk = read32(0x20)
print("unk: 0x%X" % unk)

version = readCString(0x30, 0x20)
kind = readCString(0x50, 0x40)
branch = readCString(0x90, 0x20)
check = read(0xB0, 0x20)
zeroes = read(0xD0, 80)
assert(x == 0x00 for x in zeroes)

print("version: %s" % version)
print("kind: %s" % kind)
print("branch: %s" % branch)

print("check: %s" % check.hex())

deadbeef = read32(0x120)
print("DEADBEEF: 0x%08X" % deadbeef)
ts = read32(0x124)
print("Timestamp: 0x%08X (%s)" % (ts, datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')))

cscheck = 0xEF

n = 0x18
irom_last = irom_start
iram1_last = iram1_start
segment_count = read8(1)
segments = []
for i in range(segment_count):
  o = n
  load,length,n = dump_seg(o)

  segments += [[o,load,length]]

  last = load+length-1

  if last >= irom_start and last <= irom_end:
    assert(load >= irom_start)
    print("IROM segment from 0x%X-0x%X" % (load, load+length-1))
    irom_last = last+1

  if last >= iram1_start and last <= iram1_end:
    assert(load >= iram1_start)
    print("IRAM1 segment from 0x%X-0x%X" % (load, load+length-1))
    iram1_last = last+1

  data = read(o+8, length)
  for x in data:
    cscheck ^= x

newPort = 1443

def addr(virtualAddress):
  for segment in segments:
    [o,load,length] = segment
    offset = virtualAddress - load
    if offset >= 0 and offset < length:
      return o + 8 + offset
  assert(False)

if ts == 0x66475798 and kind == b'toniebox-esp32-eu' and version == b'v5.233.0':

  def patchMovi_12bit(o,oldVal, newVal):
    movi = read16b(addr(o+1))
    val = movi & 0xFFF
    assert(val == oldVal)
    movi &= ~0xFFF
    assert(newVal <= 0x7FF)
    movi |= newVal
    write16b(addr(o+1), movi)
    print("Patched movi instruction at 0x%X from 0x%06X to 0x%06X" % (o, oldVal, newVal))

  def nop2(o):
    write(o, bytes([0xF0, 0x3D]))

  def nop3(o):
    write(o, bytes([0x00, 0x20, 0xF0]))

  def movi(o, reg, val):
    assert(val >= 0) # Must actually be >= -0x800, but we don't support signed
    assert(val <= 0x7FF)
    #write(o, bytes([val & 0xFF, 0b1010, val >> 8, reg, 0b0010]))
    assert(False)

  # Patch rtnl.bxcl.de port
  patchMovi_12bit(0x42014338, 443, newPort)

  # Patch ota request port
  patchMovi_12bit(0x42015aeb, 443, newPort) 

  # Patch content port 
  patchMovi_12bit(0x42015c9a, 443, newPort)  

  # Patch claim port
  patchMovi_12bit(0x42015e28, 443, newPort)  

  # Patch log port
  patchMovi_12bit(0x42015ffd, 443, newPort)  

  # Patch freshness check port
  patchMovi_12bit(0x420160e0, 443, newPort)  

  #FIXME: Why doesn't this fw seem to query the /time/?


  newHostAddress = iram1_start #FIXME: !!!

  # Patch fcs.tbs.toys address
  write32(addr(0x42000708), newHostAddress)

  # Patch prod.de.tbs.toys address
  write32(addr(0x4200070C), newHostAddress)

  # Patch rtnl.bxcl.de address
  write32(addr(0x42001ee8), newHostAddress)


  # Patch password
  pw1 = read(addr(0x42001630),4)
  print("PW1: %s" % pw1.hex())
  pw2 = read(addr(0x42004be4),4)
  print("PW2: %s" % pw2.hex())


  # Ignore failed SLIX check for E0 04 ??
  nop2(addr(0x4202d9de))

  # Ignore failed SLIX check for ?? ?? 03 (only done if E0 04 check success)
  nop3(addr(0x4202d9d8))

  # Remove read for block 8
  nop3(addr(0x4202db38))

  # Remove failure for read failure for block 8
  nop3(addr(0x4202db3e))


  # Remove call which enables privacy mode
  movi(0x4202db44, 2, 0)
  #retw_n(0x4202d7ff+3)

  
if True:
  # Create a segment for our hacks
  hack_length = 0x1000
  hack_last = iram1_last + length - 1
  assert(hack_last <= iram1_end)
  n = write_seg(n, iram1_last, hack_length)
  segment_count += 1
  write8(1, segment_count)

  open("hacked-ota_2.bin", 'wb').write(image)

else:

  # Skip bytes until we are at the byte before the next 16 byte boundary
  while n & 0xF != 0xF:
    assert(read8(n) == 0x00)
    n += 1

  n += 1

  csval = read8(n-1)
  hashval = read(n+0, 0x20)

  padding = n+0+0x20
  ff = read(padding, len(image) - padding)
  assert(x == 0xFF for x in ff)

  hashcheck = hashlib.sha256(image[0:n+0]).digest()

  print("checksum: 0x%02X = calc 0x%02X?" % (csval, cscheck))
  print("hash: %s = calc %s?" % (hashval.hex(), hashcheck.hex()))






import sys

data = b''

def load(path):
  global data
  data = open(path,'rb').read()

def get(offset, length):
  return data[offset:offset+length]

def extract(name, offset, length):
  data = get(offset, length)
  open(name, 'wb').write(data)



def analyze_flash():
  load("flash.bin")

  esptool = """
  esptool.py v4.8.1
  File size: 8388608 (bytes)
  Detected image type: ESP32-S3
  Image version: 1
  Entry point: 403b61c4
  3 segments

  Segment 1: len 0x00118 load 0x3fcd0108 file_offs 0x00000018 [BYTE_ACCESSIBLE,MEM_INTERNAL,DRAM]
  Segment 2: len 0x00b90 load 0x403b6000 file_offs 0x00000138 [MEM_INTERNAL,IRAM]
  Segment 3: len 0x027f4 load 0x403ba000 file_offs 0x00000cd0 [MEM_INTERNAL,IRAM]
  Checksum: f7 (valid)
  Validation Hash: 85456bba097dfe09446eb7a0973e5090b3fe6aece39e43969b96951ee53d0f97 (valid)
  """

  # Partition table for https://github.com/espressif/esp-idf/blob/master/components/partition_table/gen_esp32part.py:
  # python3 ./gen_esp32part.py partitionTable.bin partitionTable.csv
  extract("partitionTable.bin", 0x9000, 0xC00)

  # Based on the table:
  extract("phy_init.bin", 0xa000, 4*0x400)

  # Stores the wifi settings and some factory information
  extract("nvs.bin", 0xb000, 16*0x400)

  # For:
  # sudo mount -o loop,offset=0 assets.bin /mnt/Temporary/ -t vfat
  extract("assets.bin", 0xf000, 1408*0x400)

  # Shows which OTA partition to use.
  # 2 Pages of 0x1000 each.
  # I assume first word is the sequence counter.
  # A bit later the index of the active OTA partition
  extract("otadata.bin", 0x16f000, 8*0x400)

  # OTA Partitions (firmware images)
  extract("ota_0.bin", 0x180000, 2176*0x400)
  extract("ota_1.bin", 0x3a0000, 2176*0x400)
  extract("ota_2.bin", 0x5c0000, 2176*0x400)

  # Empty for me
  extract("coredump.bin", 0x7e0000, 128*0x400)


  #phy_init,data,phy,0xa000,4K,
  #nvs,data,nvs,0xb000,16K,
  #assets,data,fat,0xf000,1408K,
  #otadata,data,ota,0x16f000,8K,
  #ota_0,app,ota_0,0x180000,2176K,
  #ota_1,app,ota_1,0x3a0000,2176K,
  #ota_2,app,ota_2,0x5c0000,2176K,
  #coredump,data,coredump,0x7e0000,128K,



def analyze_ota_2():
  esptool = """
  esptool.py v4.8.1
  File size: 2228224 (bytes)
  Detected image type: ESP32-S3
  Image version: 1
  Entry point: 40374efc
  6 segments

  Segment 1: len 0x1c270 load 0x3c0c0020 file_offs 0x00000018 [DROM]
  Segment 2: len 0x03d80 load 0x3fc93200 file_offs 0x0001c290 [BYTE_ACCESSIBLE,MEM_INTERNAL,DRAM]
  Segment 3: len 0xb4f14 load 0x42000020 file_offs 0x00020018 [IROM]
  Segment 4: len 0x0412c load 0x3fc96f80 file_offs 0x000d4f34 [BYTE_ACCESSIBLE,MEM_INTERNAL,DRAM]
  Segment 5: len 0x0f144 load 0x40374000 file_offs 0x000d9068 [MEM_INTERNAL,IRAM]
  Segment 6: len 0x0003c load 0x600fe000 file_offs 0x000e81b4 [RTC_DRAM,RTC_IRAM]
  Checksum: 4d (valid)
  Validation Hash: 384e16c3e1967bdf6ffc2c0e16faacb2c7426e13310b126b35b325929fb8aef6 (valid)
  """

  load("ota_2.bin")

  extract("ota_2/some_fat.bin", 0x9150, 0x0001c290-0x9150)




analyze_flash()
analyze_ota_2()

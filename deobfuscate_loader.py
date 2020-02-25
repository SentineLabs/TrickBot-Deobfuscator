"""
Loader progression:
2017 - Started obfuscating the resource section name
2017 - Custom base64 of strings
2018 - Adds UAC bypass, Heavens gate and function obfuscation
2019 - XORd config embedded at offsets along with XOR key

Added some code from Graham Austin which is on CAPE sandbox to my original decoder since they moved to a XORd config setup.
Fixed some of the code related to finding the config and key offsets, original code from CAPE.
Added deobfuscation and rebuilding loader statically from my 2018 code.
"""
import pefile
import sys
import struct
import mylzo
import re
import yara
import hashlib
from Crypto.Cipher import AES

#From Graham Austin
rule_source = '''
rule TrickBot
{
    meta:
        author = "grahamaustin"
        description = "TrickBot Payload"
        cape_type = "TrickBot Payload"
    strings:
        $snippet1 = {B8 ?? ?? 00 00 85 C9 74 32 BE ?? ?? ?? ?? BA ?? ?? ?? ?? BF ?? ?? ?? ?? BB ?? ?? ?? ?? 03 F2 8B 2B 83 C3 04 33 2F 83 C7 04 89 29 83 C1 04 3B DE 0F 43 DA}
    condition:
        ($snippet1)
}
'''
#From Graham Austin
def yara_scan(raw_data, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == 'TrickBot':
            for item in match.strings:
                if item[1] == rule_name:
                    addresses[item[1]] = item[0]
    return addresses



def get_addr_from_off(pe, off):
	ret = None
	for s in pe.sections:
		if s.contains(off):
			ret = off - s.VirtualAddress - s.PointerToRawData
			break
	return (s,ret)


def find_add_val(data):
	off = data.find('\x81\xc1')
	return struct.unpack_from('<I', data[off+2:])[0]


def find_xor_key(data):
	l = 0
	xoff = 0
	off = data.find('\x8b\xc8\xfc\x57')
	blob = data[off+4:]
	off = blob[:50].find('\x68')
	if off != -1:
		l = struct.unpack_from('<I', blob[off+1:])[0]
	else:
		off = blob[:50].find('\x6a')
		if off != -1:
			l = struct.unpack_from('<B', blob[off+1:])[0]
	off = blob[:50].find('\x83\xc0')
	if off != -1:
		xoff = struct.unpack_from('<B', blob[off+2:])[0]

	return (l,xoff)


def Word(data):
	return struct.unpack_from('<H', data)[0]

def Dword(data):
	return struct.unpack_from('<I', data)[0]

def gen_vals(off, tbl, add_val):
	start = off
	orig = off
	guard = 0xfff0
	vals = []
	val = Word(tbl)
	i = 0
	while val != 0:
		if val >= guard:
			val -= guard
			val <<= 2
			temp = val+add_val
			val = Dword(tbl[temp:])
		start += val
		vals.append(start)
		i += 2
		val = Word(tbl[i:])
	return vals

def derive_key(n_rounds,input_bf):
    intermediate = input_bf
    for i in range(0, n_rounds):
        sha = hashlib.sha256()
        sha.update(intermediate)
        current = sha.digest()
        intermediate += current
    return current

#expects a str of binary data open().read()
def trick_decrypt(data):
    key = derive_key(128, data[:32])
    iv = derive_key(128,data[16:48])[:16]
    aes = AES.new(key, AES.MODE_CBC, iv)
    mod = len(data[48:]) % 16
    if mod != 0:
        data += '0' * (16 - mod)
    return aes.decrypt(data[48:])[:-(16-mod)]

#From grahamaustin - modified by jreaves
def find_xor_config(data):
	try:
		pe = pefile.PE(data=data)
		base = pe.OPTIONAL_HEADER.ImageBase
		memdata = pe.get_memory_mapped_image()
	except:
		return None


	snippet = yara_scan(data, '$snippet1')
	if not snippet:
		return None
	offset = int(snippet['$snippet1'])
	key_len     = struct.unpack("<L", data[offset+10:offset+14])[0]
	key_offset  = struct.unpack("<L", data[offset+15:offset+19])[0] - base
	#print(hex(key_offset-base))
	#(s,key_offset) = get_addr_from_off(pe,key_offset-base)
	#print(hex(key_offset))
	data_offset = struct.unpack("<L", data[offset+20:offset+24])[0] - base
	#(s,data_offset) = get_addr_from_off(pe,data_offset)
	size_offset = struct.unpack("<L", data[offset+53:offset+57])[0] - base
	#(s,size_offset) = get_addr_from_off(pe,size_offset)
	size = size_offset - data_offset
	key = memdata[key_offset:key_offset+key_len]
	#key = [key[i:i+4] for i in range(0, len(key), 4)]
	#key_len2 = len(key)
	a = memdata[data_offset:data_offset+size]
	#a = xor_data(a,key,key_len2)
	a = bytearray(a)
	key = bytearray(key)
	for i in range(len(a)):
		a[i] ^= key[i%len(key)]
	return trick_decrypt(str(a))

def decoder(data):
	conf = {}
	pe = pefile.PE(data=data)
	mapped = pe.get_memory_mapped_image()
	oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint

	call_off = mapped[oep:].find('\xe8')
	next_off = struct.unpack_from('<I', mapped[oep+call_off+1:])[0]
	tbl_off = oep+call_off+5
	tbl = mapped[tbl_off:]
	blob = mapped[oep+call_off+5+next_off:]
	tbl_add_val  = find_add_val(blob)

	vals = gen_vals(tbl_off, tbl, tbl_add_val)

	(l,xoff) = find_xor_key(blob)

	keystream = bytearray(mapped[vals[-1]+xoff:vals[-1]+xoff+l])

	decoded_data = []

	for i in range(len(vals)-1):
		l = vals[i+1] - vals[i]
		a = vals[i]
		temp_data = bytearray(mapped[a:a+l])
		for j in range(len(temp_data)):
			temp_data[j] ^= keystream[j%len(keystream)]
		decoded_data.append((a,l,temp_data))

	lzo_compressed = [x for x in decoded_data if x[2][0] == 0x1a]

	for i in range(len(lzo_compressed)):
		temp = mylzo.lzo_decompress_block(str(lzo_compressed[i][2]))
		temp = 'MZ' + temp[2:]
		c = find_xor_config(temp)
		if c != None:
			length = struct.unpack_from('<I',c)[0]
			if length < 4000:
				#print c[8:length+8]
				conf['CONFIG'] = c[8:length+8]
				ips = re.findall('''<srv>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:[0-9]+)''', c[8:length+8])
				conf.update({"ips": ips})

	return conf


if __name__ == "__main__":
	data = open(sys.argv[1], 'rb').read()
	t = decoder(data)
	print(t)

base_addr = 0x1007961A
struct_size = 14

i = 0
while ida_bytes.get_dword(base_addr+i)  != 0:
	address = ida_bytes.get_dword(base_addr+i)
	size = ida_bytes.get_dword(base_addr+i+4)
	XOR_key = ida_bytes.get_byte(base_addr+i+12)
	j = 0
	for b in range(size):
		patch_byte(address+j,ida_bytes.get_byte(address+j) ^ XOR_key)
		j = j+1

	i += struct_size


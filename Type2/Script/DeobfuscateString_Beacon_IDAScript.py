
base_of_struct_array = 0x1004991C
struct_size = 8 # size = 8 in Cobalt Strike Beacon
i = 0
while ida_bytes.get_dword(base_of_struct_array+i)  != 0:
	address = ida_bytes.get_dword(base_of_struct_array+i)
	size = ida_bytes.get_word(base_of_struct_array+i+4)
	XOR_key = ida_bytes.get_byte(base_of_struct_array+i+6)
	j = 0
	for b in range(size):
		patch_byte(address+j,ida_bytes.get_byte(address+j) ^ XOR_key)
		j = j+1
	i += struct_size


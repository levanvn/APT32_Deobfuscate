from capstone.x86 import *
from capstone import *
from keystone import *
log_filename = r"log2.txt"
f = open(log_filename,"a")

def write_log(data):
	f.write(data)
	f.write("\n")
def patch(image, offset, patch_data):
    i = 0
    for b in patch_data:
        image[offset + i] = b
        i += 1


def patch_code(image, address,offset, assembly):
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, _ = ks.asm(assembly, address)
    patch_data = ''.join(chr(e) for e in encoding)
    patch(image, offset, patch_data)
    return len(encoding)

def  patch_IDA(address, size, data):
	i = 0
	for j in range(size):
		patch_byte(address+i, data[i])
		i +=1

def Find_stack_address(address, level, startEA):
	sp = get_spd(address)
	ea = PrevHead(address)
	while get_spd(ea)-4*level != sp:
		if ea < startEA:
			return 0
		ea = PrevHead(ea)
	return ea 

def Fix_call(image,startEA, endEA):
	assembly = ''
	pattern = "8D 64 24 ??" #lea esp, [esp +- ??]
	binary_ea = FindBinary(endEA, SEARCH_UP, pattern)
	if binary_ea < startEA:
		return
	code = GetManyBytes(binary_ea,32)
	md = Cs(CS_ARCH_X86, CS_MODE_32)
	md.detail = True
	try:
		insns = md.disasm(code, binary_ea)
		insn1 = insns.next()
		insn2 = insns.next()
		insns.close()
	except StopIteration:
		return 0
	if insn1.operands[1].type == X86_OP_MEM and  insn1.reg_name(insn1.operands[1].mem.base) == 'esp' and insn1.operands[1].mem.disp > 4:
		if insn2.mnemonic == 'ret':
			call_function  = Find_stack_address(insn2.address,1,startEA)
			return_address_push  = Find_stack_address(insn2.address,2,startEA)
			if call_function == 0 or return_address_push == 0:
				write_log("Suspicious basic block at 0x%x"%startEA)
				return 0
			code = GetManyBytes(call_function,32)
			try:
				insns = md.disasm(code, call_function)
				insn_1 = insns.next()
				insns.close()
			except StopIteration:
				return 0
			code = GetManyBytes(return_address_push,32)
			try:
				insns = md.disasm(code, call_function)
				insn_2 = insns.next()
				insns.close()
			except StopIteration:
				return 0

			if insn_1.operands[0].type == X86_OP_REG:
				assembly = "call %s"%insn_1.reg_name(insn_1.operands[0].reg)
				write_log("Patch at 0x%08x: \t"%return_address_push + assembly )
			if insn_1.operands[0].type == X86_OP_IMM:
				call_addr = insn_1.operands[0].imm
				assembly = "call 0x%08x"%call_addr
				write_log("Patch at 0x%08x: \t"%return_address_push + assembly )

			if insn_2.operands[0].imm != endEA:
				write_log( "Fix RET call: Suspicious return address in push/ret 0x%x"%startEA)
			
			op_len = patch_code(image,return_address_push, return_address_push-startEA, assembly)
			patch(image, return_address_push -startEA+op_len,(endEA- return_address_push-op_len)*'\x90')

		if insn2.mnemonic == 'jmp':
			ea_push1 = Find_stack_address(insn2.address,1,startEA)
			code = GetManyBytes(ea_push1,10)
			try:
				insns = md.disasm(code, ea_push1)
				insn_push = insns.next()
				insns.close()
			except StopIteration:
				return 0
			if insn_push.operands[0].imm != endEA:
				write_log ("Fix JMP call: Suspicious return address in push/ret at 0x%x"%startEA)

			if insn2.operands[0].type == X86_OP_REG:
				assembly = "call %s"%insn2.reg_name(insn2.operands[0].reg)
				write_log(assembly+ " at 0x%x"%ea_push1)
			if insn2.operands[0].type == X86_OP_IMM:
				assembly = "call 0x%08x"%insn2.operands[0].imm
			op_len = patch_code(image,ea_push1, ea_push1-startEA, assembly)
			patch(image, ea_push1 -startEA+op_len,(endEA- ea_push1-op_len)*'\x90')


for fva in Functions():
	function = idaapi.get_func(fva)
	for block in idaapi.FlowChart(function):
		begin = block.startEA
		end = block.endEA
		if end-begin != 0:
			code = GetManyBytes(begin,end-begin)
			image = bytearray()
			image.extend(code)
			Fix_call(image, begin, end)
			patch_IDA(begin, end -begin, image)

f.close()
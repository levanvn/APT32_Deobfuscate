from capstone.x86 import *
from capstone import *
from keystone import *

log_filename = r"log1.txt"
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


def Check_stack_pointer(address1, address2):
	sp1 = get_spd(address1)
	sp2 = get_spd(address2)
	return sp1 == sp2

def Find_Pattern_1(image, start_ea, end_ea, code):

	list_ = []
	start_junk_code = 0
	end_junk_code = 0
	deep_1 = 0
	deep_2 = 0


	for insn in md.disasm(code, start_ea):
		if insn.mnemonic == 'lea' and insn.operands[0].type == X86_OP_REG and insn.reg_name(insn.operands[0].reg) == 'esp' and insn.operands[1].type == X86_OP_MEM and  insn.reg_name(insn.operands[1].mem.base) == 'esp' and insn.operands[1].mem.disp == -4:
			list_.append(insn.address)
			deep_1 += 1
		if insn.mnemonic == 'mov' and insn.operands[0].type == X86_OP_MEM and insn.reg_name(insn.operands[0].mem.base) == 'esp' and insn.operands[0].mem.disp == 0:
			if list_:
				start_junk_code = list_.pop()
			end_junk_code = insn.address
			if not Check_stack_pointer(start_junk_code+4, end_junk_code):
				write_log( "Type 1: supcilious stack pointer 0x%x"%start_ea)
				continue
			else:
				write_log("Detect push junk code: begin-end: \t\t0x%x - 0x%x"%(start_junk_code,insn.address))
				if insn.operands[1].type == X86_OP_IMM:
					value = insn.operands[1].imm
					assembly = 'push 0x%08x' % value
					if image[start_junk_code-start_ea] != 0x90:

						op_len = patch_code(image,start_junk_code, start_junk_code-start_ea, assembly)
						patch(image, start_junk_code -start_ea+op_len,(end_junk_code+insn.size- start_junk_code-op_len)*'\x90')
				if insn.operands[1].type == X86_OP_REG:
					
					
					reg_value = insn.reg_name(insn.operands[1].reg)
					assembly = 'push %s' % reg_value
					if image[start_junk_code-start_ea] != 0x90:
						op_len = patch_code(image,start_junk_code, start_junk_code-start_ea, assembly)
						patch(image, start_junk_code -start_ea+op_len,(end_junk_code+insn.size- start_junk_code-op_len)*'\x90')


def Find_Pattern_2(image, start_ea, end_ea, code):
	start_junk_code = 0
	reg_value = ''
	pattern = "8D 64 24 04" #lea esp, [esp + 4]
	end_junk_code = find_binary(end_ea, SEARCH_UP, pattern)

	if end_junk_code < start_ea or end_junk_code == BADADDR:
		return
	for insn in md.disasm(code, start_ea):
		if insn.address >= end_junk_code:
			break
		if insn.mnemonic == 'mov' and insn.operands[1].type == X86_OP_MEM and insn.reg_name(insn.operands[1].mem.base) == 'esp' and insn.operands[1].mem.disp == 0:
			if insn.operands[0].type == X86_OP_REG:
				if Check_stack_pointer(insn.address, end_junk_code):
					start_junk_code = insn.address
					reg_value = insn.reg_name(insn.operands[0].reg)
			if insn.operands[0].type == X86_OP_IMM:
				write_log( "Supcilious block: \t\t0x%x"%start_ea)
	if start_junk_code != 0:
		write_log("Detect pop junk code begin-end:\t\t 0x%x - 0x%x"%(start_junk_code,insn.address))

		assembly = 'pop %s' % reg_value
		if image[start_junk_code-start_ea] != 0x90:
			op_len = patch_code(image,start_junk_code, start_junk_code-start_ea, assembly)
			patch(image, start_junk_code-start_ea+op_len,(end_junk_code+4- start_junk_code-op_len)*'\x90')

def Check_same_jump(begin, end):
	branch = ["JZ","JP", "JO","JS", "JG", "JB", "JA","JL","JE"]
	branch_ = ["JNZ" , "JNP", "JNO", "JNS", "JLE", "JNB", "JBE","JGE","JNE", "JAE"]
	pattern = "8D 64 24 ??" #lea esp, [esp +- ??]
	binary_ea = find_binary(end, SEARCH_UP, pattern)
	if binary_ea < begin: 
		return
	code = get_bytes(begin,end-begin)
	image = bytearray(code)
	md = Cs(CS_ARCH_X86, CS_MODE_32)
	md.detail = True
	code = get_bytes(begin,32)
	try:
		insns = md.disasm(code, begin)
		insn1 = insns.next()
		insns.close()
	except StopIteration:
		return 0
	code = get_bytes(prev_head(end),32)
	try:
		insns = md.disasm(code, prev_head(end))
		insn_last = insns.next()
		insns.close()
	except StopIteration:
		return 0

	if (insn1.mnemonic.upper() in branch and insn_last.mnemonic.upper() in branch_ and insn1.operands[0].imm == insn_last.operands[0].imm) or \
		(insn1.mnemonic.upper() in branch_ and insn_last.mnemonic.upper() in branch and insn1.operands[0].imm == insn_last.operands[0].imm):
		assembly = 'jmp 0x%x'% insn1.operands[0].imm
		op_len = patch_code(image,insn1.address, 0 , assembly)
		patch(image, op_len,(end-begin-op_len)*'\x90')
		write_log( "Same jump at basic block: \t\t0x%08x"% begin )
		patch_IDA(begin,end-begin, image)


def Patch_jmp_5(image,start_ea,end_ea):
	end_basic_block = prev_head(end_ea)
	code = get_bytes(end_basic_block,10)
	md = Cs(CS_ARCH_X86, CS_MODE_32)
	md.detail = True
	try:
		insns = md.disasm(code, end_basic_block)
		insn1 = insns.next()
		insns.close()
	except StopIteration:
		return 0

	if insn1.mnemonic == 'jmp' and insn1.operands[0].type == X86_OP_IMM and insn1.operands[0].imm == end_ea and insn1.size == 5:
		write_log( "Patch jmp $+5 address: \t\t0x%x " %(insn1.address))
		patch(image, len(image)-5, 5*'\x90')

for fva in Functions():
	function = idaapi.get_func(fva)
	for block in idaapi.FlowChart(function):
		begin = block.start_ea
		end = block.end_ea

		if end-begin != 0: 
			code = get_bytes(begin,end-begin)
			image = bytearray()
			image.extend(code)
			md = Cs(CS_ARCH_X86, CS_MODE_32)
			md.detail = True
			Find_Pattern_1(image,begin,end,code)
			Find_Pattern_2(image,begin,end,code)
			Patch_jmp_5(image,begin,end)
			patch_IDA(begin, end -begin, image)
			if prev_head(begin) != BADADDR:
				Check_same_jump(prev_head(begin),end)

f.close()

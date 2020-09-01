#python2.7
__AUTHOR__ = "vuonglvm"

import pefile
from capstone.x86 import *
from capstone import *
from keystone import *
import struct
import traceback
import argparse


def write_log(file,data):
    file.write(data)
    file.write("\n")


def patch(image, image_base, address, patch_data):
    i = 0
    for b in patch_data:
        image[address - image_base + i] = b
        i += 1

def patch_code(image, image_base, address, assembly):
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, _ = ks.asm(assembly, address)
    patch_data = ''.join(chr(e) for e in encoding)
    return patch(image, image_base, address, patch_data)

    
def Check_Instruction(image,rva, image_base):
    branch = ["JZ","JP", "JO","JS", "JG", "JB", "JA","JL","JE","JNZ" , "JNP", "JNO", "JNS", "JLE", "JNB", "JBE","JGE","JNE", "JAE"]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    b = 3
    for i in range(3):
        
        code = image[rva-b:rva-b+20]
        if  b == 3 and code[0] != 0x66:  # Prefix operand-size  
            b = b-1
            continue
        b = b-1
        try:
            insns = md.disasm(code, image_base+rva)
            insn = insns.next()
            insn_2 = insns.next()
            insns.close()
        except StopIteration:
            continue
        if (insn.mnemonic == 'test' or insn.mnemonic == 'cmp') and insn_2.mnemonic.upper() in branch and len(insn.operands) == 2 and  insn.operands[0].type == X86_OP_MEM and insn.operands[1].type == X86_OP_IMM : 
            print "Disp: 0x%08x"%insn.operands[0].mem.disp
            print "IMM: 0x%08x"%insn.operands[1].imm
            print "VA: 0x%08x"%(image_base+rva-i)     
            return rva-b-1
        
    return 0

def Check_compare(image, rva,image_base,file):
    try:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        code = image[rva:rva+0x20]
        insns = md.disasm(code, image_base+rva)
        insn = insns.next()
        insn_2 = insns.next()
        if (insn.mnemonic == 'test' or insn.mnemonic == 'cmp') and len(insn.operands) == 2 and  insn.operands[0].type == X86_OP_MEM and insn.operands[1].type == X86_OP_IMM:   
            assembly = "jmp 0x%08x"%insn_2.operands[0].imm
            write_log(file, "Asm: \t"+assembly)
            write_log(file,"Patch at: \t0x%08x"%(rva+image_base))
            patch_code(image,image_base,image_base+rva, assembly)

        insns.close()
    except StopIteration:
        traceback.print_exc()
        return 0
    except Exception as ex:
        traceback.print_exc()
        

def parse_relocations(image, module_base_address, pe, data_rva, rva, size):
    data = image[  data_rva :   data_rva + size]
    file_offset = pe.get_offset_from_rva(data_rva)

    entries = []
    for idx in range(len(data) / 2):

        entry = pe.__unpack_data__(
            pe.__IMAGE_BASE_RELOCATION_ENTRY_format__,
            data[idx * 2:(idx + 1) * 2],
            file_offset=file_offset)

        if not entry:
            break
        word = entry.Data

        relocation_type = (word >> 12)
        relocation_offset = (word & 0x0fff)
        relocation_data = pefile.RelocationData(
            struct=entry,
            type=relocation_type,
            base_rva=rva,
            rva=relocation_offset + rva)

        if relocation_data.struct.Data > 0 and \
                (relocation_data.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW'] or
                 relocation_data.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_DIR64']):
            entries.append(relocation_data)
        file_offset += entry.sizeof()

    
    return entries

def get_relocations(pe, image, image_base):
    try:
        relocations = []
        relocation_table = pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']]
        rva = relocation_table.VirtualAddress
        size = relocation_table.Size
        if size == 0:
            return []
        
        rlc_size = pefile.Structure(pe.__IMAGE_BASE_RELOCATION_format__).sizeof()
        end = rva + size

        while rva < end:
            try:
                rlc = pe.__unpack_data__(
                    pe.__IMAGE_BASE_RELOCATION_format__,
                    image[ rva: rva + rlc_size],
                    file_offset=pe.get_offset_from_rva(rva))
            except pefile.PEFormatError:
                rlc = None

            if not rlc:
                break
            print ("rlc.VirtualAddress: %x, rlc.SizeOfBlock: %x"% (rlc.VirtualAddress,rlc.SizeOfBlock))
            relocation_entries = parse_relocations(image, image_base, pe, rva + rlc_size, rlc.VirtualAddress,
                                                   rlc.SizeOfBlock - rlc_size)
            
            relocations.append(
                pefile.BaseRelocationData(
                    struct=rlc,
                    entries=relocation_entries))

            if not rlc.SizeOfBlock:
                break
            rva += rlc.SizeOfBlock
        
        return relocations
    except Exception as ex:
        print(str(ex))


def main():
    f = open("Type2_log.txt","a")

    parser = argparse.ArgumentParser(description="APT32 Type 2 Deobfuscate")
    parser.add_argument('-in',dest="input",default=None,help="File with data", required=True)
    parser.add_argument('-out',dest="outfile",default=None, help="Where to dump the output", required=False)

    args = parser.parse_args()
    print ('[+] Parse PE file')
    pe = pefile.PE(args.input, fast_load=True)
    if args.outfile is None:
        args.outfile = args.input + ".out"
    image_base = pe.OPTIONAL_HEADER.ImageBase
    address_of_entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    print ('[+] Map PE file')
    memory_mapped_image = bytearray(pe.get_memory_mapped_image())
    relocations = get_relocations(pe,memory_mapped_image, image_base)
    for relocation in relocations:
        for relocation_entry in relocation.entries:
            addr = Check_Instruction(memory_mapped_image,relocation_entry.rva, image_base)
            if addr != 0:
                print "\n"
                Check_compare(memory_mapped_image,addr,image_base,f)

    for section in pe.sections:
        VirtualAddress_adj = pe.adjust_SectionAlignment(section.VirtualAddress,
                                                        pe.OPTIONAL_HEADER.SectionAlignment,
                                                        pe.OPTIONAL_HEADER.FileAlignment)
        if section.Misc_VirtualSize == 0 or section.SizeOfRawData == 0:
            continue
        if section.SizeOfRawData > len(memory_mapped_image):
            continue
        if pe.adjust_FileAlignment(section.PointerToRawData, pe.OPTIONAL_HEADER.FileAlignment) > len(memory_mapped_image):
            continue

        pe.set_bytes_at_rva(VirtualAddress_adj, bytes(memory_mapped_image[VirtualAddress_adj: VirtualAddress_adj + section.SizeOfRawData]))
        
    print ('[+] Save to file ' + args.outfile)

    pe.write(args.outfile)
if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print ('Exception', e)
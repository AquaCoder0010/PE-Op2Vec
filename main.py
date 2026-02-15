import os
import pefile
from capstone import *

def find_exe_files(root_dir, exe_limit=None):
    exe_files = []
    for dirpath, _, filenames in os.walk(root_dir):
        for file_ in filenames:
            if file_.lower().endswith('.exe'):
                full_path = os.path.join(dirpath, file_)
                exe_files.append(full_path)
                if exe_limit is not None and len(exe_files) >= exe_limit:
                    return exe_files
    return exe_files


def get_opcodes_from_pe(file_path):
    try:
        pe = pefile.PE(file_path)
        eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        code_section = None
        for section in pe.sections:
            if section.contains_rva(eop):
                code_section = section
                break
        if not code_section:
            return []
        
        # Disassemble the code section
        raw_code = code_section.get_data()
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        opcodes = [i.mnemonic for i in md.disasm(raw_code, code_section.VirtualAddress)]
        return opcodes
    except Exception as e:
        return []

if __name__ == "__main__":
    WINDOWS_PATH = "/home/aqua/mount-file/temp-sda3/Windows"
    PE_list = find_exe_files(WINDOWS_PATH, 10_000)

    corpus = [get_opcodes_from_pe(curr_PE) for curr_PE in PE_list[:100]]
    corpus = [app for app in corpus if app]

    unique_opcodes = set(word for app in corpus for word in app)
    print(f"total unique opcodes : {len(unique_opcodes)}")
    
    print(len(unique_opcodes))

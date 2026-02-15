import time

import os
import pefile
from capstone import *

from gensim.models import Word2Vec
from gensim.models.doc2vec import Doc2Vec, TaggedDocument

from tqdm import tqdm 

MODEL_NAME = "pe_malware_d2v.model"
TEST_DIR = "data/raw"

def find_exe_files(root_dir, exe_limit=None):
    exe_files = []
    for dirpath, _, filenames in tqdm(os.walk(root_dir), desc="Scanning directories"):
        for file_ in filenames:
            if file_.lower().endswith('.exe'):
                full_path = os.path.join(dirpath, file_)
                exe_files.append(full_path)
                if exe_limit is not None and len(exe_files) >= exe_limit:
                    return exe_files
    return exe_files


def get_opcodes(file_path):
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

def train():
    WINDOWS_PATH = "/home/aqua/mount-file/temp-sda3/Windows"
    PE_list = find_exe_files(WINDOWS_PATH, 10_000)
    PE_count = len(PE_list)
    

    print("Generating Corpus ... ")
    corpus = [TaggedDocument(get_opcodes(PE_list[i]), tags=[str(i)]) for i in range(PE_count) if get_opcodes(PE_list[i])]

    corpus_nt = [get_opcodes(curr_PE) for curr_PE in PE_list if curr_PE]
    unique_opcodes = set(word for app in corpus_nt for word in app)
    
    print(f"total unique opcodes : {len(unique_opcodes)}")
    print(len(unique_opcodes))

    print("Done >3")    

    op2vec_model = Doc2Vec(
        vector_size=100,
        window=5,       
        min_count=1,    
        workers=4,      
        dm=0            
    )

    print("Starting to build vocal") 
    op2vec_model.build_vocab(corpus)
    
    print("Starting training...")
    start_time = time.time()

    op2vec_model.train(corpus, total_examples=op2vec_model.corpus_count, epochs=50)

    op2vec_model.save(MODEL_NAME)
    print(f"Training complete in {time.time() - start_time:.2f} seconds.")


def test():
    d2v_model = Doc2Vec.load(MODEL_NAME)
    vector = d2v_model.infer_vector(["mov", "push", "xor"])
    
    files = find_exe_files(os.getcwd() + "/" + TEST_DIR)
    for pe_file in files:
        curr_opcodes = get_opcodes(pe_file)
        curr_vector = d2v_model.infer_vector(curr_opcodes)
        print(curr_vector)


if __name__ == "__main__":
    #train()
    #test()
    pass
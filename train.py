import os
import time
import pefile
from capstone import *


from pathlib import Path

from gensim.models import Word2Vec
from gensim.models.doc2vec import Doc2Vec, TaggedDocument
from gensim.matutils import cossim

from multiprocessing import Pool, cpu_count

from tqdm import tqdm 

MODEL_NAME = "pe_malware_d2v.model"
TEST_DIR = "data/raw"

def get_opcodes(file_path):
    try:
        pe = pefile.PE(file_path)
        eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        code_section = next(
            (s for s in pe.sections if s.contains_rva(eop)),
            None
        )
        if not code_section:
            return []
        raw_code = code_section.get_data()
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        return [f"{i.mnemonic} {i.op_str}" for i in md.disasm(raw_code, code_section.VirtualAddress)]
    except Exception:
        return []


def process_file(args):
    idx, filepath = args
    return idx, get_opcodes(filepath)

def train():
    CWD = Path.cwd()
    DATASET_PATH = CWD / "data" / "train"

    print("Generating Corpus ... ")
    
    exe_files = list(DATASET_PATH.rglob('*.exe'))
    indexed_files = list(enumerate(exe_files))

    print(f"Disassembling {len(exe_files)} files using {cpu_count()} cores...")
    with Pool(processes=cpu_count()) as pool:
        results = list(tqdm(
            pool.imap_unordered(process_file, indexed_files),
            total=len(indexed_files),
            desc="Processing files"
        ))

    successful = [(idx, opcodes) for idx, opcodes in results if opcodes]
    corpus = [TaggedDocument(opcodes, tags=[str(idx)]) for idx, opcodes in successful]

    unique_opcodes = set()
    for _, opcodes in successful:
        unique_opcodes.update(opcodes)        
    
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
        
    vector = d2v_model.infer_vector(["mov", "push"])

    similarities = d2v_model.dv.most_similar([vector], topn=5)
    
    print("Most similar words/documents:")
    for similar_word, similarity_score in similarities:
        print(f"{similar_word}: {similarity_score}")
    


if __name__ == "__main__":
    train()
    #test()
    pass
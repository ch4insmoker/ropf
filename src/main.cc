#include "main.h"

void rop_search(cs_insn *memory, size_t count, unsigned long long base_address, unsigned int depth) {

    if (memory[count].address < base_address) {
        printf("0x%llx", memory[count].address);
        return;
    }

    printf("0x%llx: ", memory[count].address);
    for (size_t j = count - depth; j < count; j++) {
        printf("%s %s; ", memory[j].mnemonic, memory[j].op_str);
    }
}

void do_it(size_t  raw_data_size, unsigned long long base_address, unsigned int depth,FILE *fp, size_t  p_t_rawdata) {

    cs_insn *insn;
    csh handle;
    size_t count;

    fseek(fp, 0 ,SEEK_SET);
    uint8_t *section_buffer = (uint8_t *)malloc(raw_data_size);
    std::memset(section_buffer, 0, raw_data_size);
    fseek(fp, p_t_rawdata ,SEEK_SET);
    fread(section_buffer, raw_data_size, 1, fp);

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        std::cout << "Error occurred" << std::endl;
        exit(-1);
    }

    count = cs_disasm(handle, section_buffer, raw_data_size-1, base_address, 0, &insn);
    int c = 0;
    if (count > 0) {
        for (size_t j = 0; j < count; j++) {
            if (insn[j].bytes[0] == 0xc3) {
                for (int i = 0; i < depth; i++) {
                    rop_search(insn, j, base_address, depth - i);
                    printf("%s %s\n" , insn[j].mnemonic, insn[j].op_str);
                }
            }
        }

        cs_free(insn, count);
    } else
        printf("ERROR: Failed to disassemble given code!\n");

    cs_close(&handle);
}

void handle_pe(FILE *fp, unsigned int depth) {
    fseek(fp,0,SEEK_SET);
    fread(&DOS_HDR,  sizeof(ROP_IMAGE_DOS_HEADER), 1, fp);

    fseek(fp,DOS_HDR.e_lfanew,SEEK_SET);
    fread(&NT_HDR, sizeof(ROP_IMAGE_NT_HEADERS64), 1, fp);
    
    DWORD entry_point = NT_HDR.OptionalHeader.ImageBase;
    DWORD num_of_sections = NT_HDR.FileHeader.NumberOfSections;

    for (int i = 0; i < num_of_sections; i++ ) {
         fseek(fp,DOS_HDR.e_lfanew + 4 + sizeof(ROP_IMAGE_FILE_HEADER) + sizeof(ROP_IMAGE_OPTIONAL_HEADER64) + (i * sizeof(ROP_IMAGE_SECTION_HEADER)) ,SEEK_SET);
         fread(&section, sizeof(ROP_IMAGE_SECTION_HEADER), 1, fp);


        if (strcmp(".text", (char*)section.Name) == 0) {
            length = section.Misc.VirtualSize;
            VA = section.VirtualAddress;
            p_t_rawdata = section.PointerToRawData;
            raw_data_size = section.SizeOfRawData;
        }
        // if (section.Characteristics & ROP_IMAGE_SCN_MEM_EXECUTE) {
        //     printf("%s is executable section\n", (char*)section.Name);
        // },
    }

    do_it(raw_data_size, entry_point + VA, depth, fp, p_t_rawdata);
}

void handle_elf(FILE *fp, unsigned int depth) {
    fseek(fp,0,SEEK_SET);
    fread(&ELF_HDR, sizeof(elf64_hdr), 1, fp);

    int shstrndx = ELF_HDR.e_shstrndx;

    off_t shstrtab_offset = ELF_HDR.e_shoff + shstrndx * ELF_HDR.e_shentsize;
    fseek(fp, shstrtab_offset, SEEK_SET);
    fread(&ELF_SHDR, sizeof(elf64_shdr), 1, fp);

    char *sections = (char *)malloc(ELF_SHDR.sh_size);
    fseek(fp, ELF_SHDR.sh_offset, SEEK_SET);
    fread(sections, ELF_SHDR.sh_size, 1, fp);

    for (int i = 0; i < ELF_HDR.e_shnum; i++) {
        off_t section_header_offset = ELF_HDR.e_shoff + i * ELF_HDR.e_shentsize;

        fseek(fp, section_header_offset, SEEK_SET);

        fread(&ELF_SHDR, sizeof(elf64_shdr), 1, fp);
        char* name = sections + ELF_SHDR.sh_name;
        if (strcmp(name, ".text") == 0) {
            raw_data_size = ELF_SHDR.sh_size;
        }
    }

    unsigned long long base_address = ELF_HDR.e_entry;
    do_it(raw_data_size, base_address, depth, fp, base_address); // lmfa0
}

int main(int argc, char**argv) {

    FILE *fp;
    uint32_t sig;
    if (argc < 2 || (fp = fopen(argv[1], "rb")) == NULL) {
        fputs("./ropf <file>\n", stderr); 
        exit(-1);
    }

    if (argc >= 3) {
        if (strcmp(argv[2], "-d") == 0) {
            depth = atoi(argv[3]);
        } 
    } else {
        depth = 5;
    }

    fread(&sig, 4, 1, fp);
    if ((uint16_t)sig == ROP_IMAGE_DOS_SIGNATURE) {
        handle_pe(fp, depth);
    } else if (sig == 0x464c457f){
        handle_elf(fp, depth);
    } else {
        fputs("invalid file format!\n", stderr);
    }

    fclose(fp);
}
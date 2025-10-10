#pragma once

#include <stdio.h>
#include <string.h>
#include <capstone/capstone.h>
#include <sys/types.h>
#include "pe_image.h"
#include "elf_image.h"

ROP_IMAGE_DOS_HEADER DOS_HDR;
ROP_IMAGE_NT_HEADERS64 NT_HDR;
ROP_IMAGE_SECTION_HEADER section;

elf64_hdr ELF_HDR;
elf64_shdr ELF_SHDR;

unsigned int depth;
unsigned long long total;

size_t  VA;
unsigned long p_t_rawdata;
size_t  raw_data_size;

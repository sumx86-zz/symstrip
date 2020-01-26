#ifndef __SYMSRIP_H
#define __SYMSRIP_H 1

#ifdef __cplusplus
extern "C" {
#endif

// global error buffer
char errbuf[0xFF];

typedef struct
{
    int fd;
    short striphdrs;       // number of headers to strip
    char *buff;
    const char *arch;
    const char *name;
    off_t size;
    Elf64_Ehdr *header;    // elf header
    Elf64_Shdr *shdr;      // Section Headers table
    Elf64_Phdr *phdr;      // Program Headers table
    uint32_t sht_size;     // file's Section Header table's size
    #define entry_size 64  // size of entry in Section Header table
}
ELF_t;

typedef struct
{
    Elf64_Shdr *shdr;  // headers of section
    Elf64_Addr *sctn;  // section address
}
ELF_Section_t;

typedef struct symlist
{
    char name[60];
    char type[10];
    char bind[10];
    char visib[10];
    char index[5];
    Elf64_Xword size;
    Elf64_Addr value;
    struct symlist *next;
}
sym_list_t;

typedef struct
{
    char *buff;         // .strtab buffer containing names
    Elf64_Off   e_off;  // offset of `.strtab`'s section header
    Elf64_Xword size;   // size   of `.strtab` section in the file
    Elf64_Off   off;    // offset of `.strtab` section in the file
}
Strtab_t;

typedef struct
{
    Elf64_Off   e_off;  // offset of `.symtab`'s section header
    Elf64_Off   off;    // offset of `.symtab` in the file
    Elf64_Xword size;   // size   of `.symtab` in the file
    Elf64_Half  e_size; // size of each entry in `.symtab`
    Elf64_Half  n_ent;  // number of entries in the symbol table
    Strtab_t    *stab;  // .strtab
}
Symtab_t;

typedef struct
{
    short dump;
    short strip;
}
ST_Opts;

typedef enum { ERR, INF } msg_t;

enum {
    ELFTYPE      = -1,
    ELFBITS      = -2,
    ELFORMAT     = -3,
    ELFSYMTB     = -4,
    ELFSHSIZE    = -5,
    ELFSHNUM     = -6,
    ELFSHSTRSIZE = -7,
    ELFSYMTBOFF  = -8
};

const char *elf_err[8] = {
    "File is not an executable!",
    "File must be 64-bit format!",
    "File is not ELF format!",
    "Symbol table not found!",
    "Invalid size of Section Header table entry!",
    "Invalid number of section headers!",
    ".shstrtab exceeds file size!",
    "Odd symbol table file offset!"
};

bool elf64_dump_symtab( ELF_t *elf, Symtab_t *symtb );
bool elf64_symstrip( ELF_t *elf, const ST_Opts *opts );
bool elf64_strip_file( ELF_t *elf, Symtab_t *symtb );

uint32_t elf64_get_sht_size( ELF_t *elf );

void elf64_print_symbols( sym_list_t *symlist );
sym_list_t * new_item( Elf64_Sym *symbol, sym_list_t *current, const char *strtab );
sym_list_t * elf64_get_symbols( ELF_t *elf, Symtab_t *symtb );

char * elf64_init_strtab( ELF_t *elf, Strtab_t *stab );

#ifdef __cplusplus
}
#endif

#endif
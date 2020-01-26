#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <elf.h>
#include <iostream>
#include "symstrip.h"
#include "itoa.h"

#define ELF64BITS 64

#define _FATAL( errbuf ){\
    puts( errbuf );\
    exit( 2 );\
}

#define ERROR( errnum, n ){\
    sprintf(\
        errbuf,\
        "%s\n", (errnum == ELFORMAT  || errnum == ELFTYPE  ||\
                 errnum == ELFBITS   || errnum == ELFSHNUM ||\
                 errnum == ELFSHSIZE || errnum == ELFSYMTB ||\
                 errnum == ELFSYMTBOFF)\
        ? elf_err[(errnum * -1) - 1]\
        : strerror( errnum ) \
    );\
    return (n == 0x00) ? 0x00 : false;\
}

#define SHUT( elf ){\
    munmap( elf->buff, elf->size );\
    close( elf->fd );\
}

/* Print usage */
void __usage( const char *prog )
{
    std::cout << "Usage: ";
    std::cout << "-f [Path to ELF binary] -d (optional) [dump symbol table]\n";
    exit( 2 );
}

/*
 * Get file architecture
 */
const char * elf64_arch( const Elf64_Ehdr *e_header )
{
    static const char *arch;
    switch ( e_header->e_machine )
    {
        case 0x02:  arch = "SPARC";   break;
        case 0x03:  arch = "x86";     break;
        case 0x08:  arch = "MPIS";    break;
        case 0x14:  arch = "PowerPC"; break;
        case 0x16:  arch = "S390";    break;
        case 0x28:  arch = "ARM";     break;
        case 0x2A:  arch = "SuperH";  break;
        case 0x32:  arch = "IA-64";   break;
        case 0x3E:  arch = "x86-64";  break;
        case 0xB7:  arch = "AArch64"; break;
        case 0xF3:  arch = "RISC-V";  break;
    }
    return arch;
}

/* symbol type */
void elf64_symtype( const u_char info, char *buff )
{
    const char *type;
    switch ( ELF64_ST_TYPE( info ) )
    {
        case STT_NOTYPE:   type = "NOTYPE";  break;
        case STT_OBJECT:   type = "OBJECT";  break;
        case STT_FUNC:     type = "FUNC";    break;
        case STT_SECTION:  type = "SECTION"; break;
        case STT_FILE:     type = "FILE";    break;
        case STT_COMMON:   type = "COMMON";  break;
        case STT_LOOS:     type = "LOOS";    break;
        case STT_HIOS:     type = "HIOS";    break;
        case STT_LOPROC:   type = "LOPROC";  break;
        case STT_HIPROC:   type = "HIPROC";  break;
        default:           type = "";        break;
    }
    strcpy( buff, type );
}

/* bind of a symbol */
void elf64_symbind( const u_char info, char *buff )
{
    const char *bind;
    switch ( ELF64_ST_BIND( info ) )
    {
        case STB_LOCAL:    bind = "LOCAL";   break;
        case STB_GLOBAL:   bind = "GLOBAL";  break;
        case STB_WEAK:     bind = "WEAK";    break;
        case STB_LOOS:     bind = "LOOS";    break;
        case STB_HIOS:     bind = "HIOS";    break;
        case STB_LOPROC:   bind = "LOPROC";  break;
        case STB_HIPROC:   bind = "HIPROC";  break;
        default:           bind = "";        break;
    }
    strcpy( buff, bind );
}

/* symbol visibility */
void elf64_symvis( const u_char other, char *buff )
{
    const char *visibility;
    switch ( ELF64_ST_VISIBILITY( other ) )
    {
        case STV_DEFAULT:    visibility = "DEFAULT";   break;
        case STV_INTERNAL:   visibility = "INTERNAL";  break;
        case STV_HIDDEN:     visibility = "HIDDEN";    break;
        case STV_PROTECTED:  visibility = "PROTECTED"; break;
        default:             visibility = "";          break;
    }
    strcpy( buff, visibility );
}

/* symbol visibility */
void elf64_symndx( const Elf64_Section st_shndx, char *buff )
{
    const char *index;
    switch ( st_shndx )
    {
        case SHN_ABS:    index = "ABS"; break;
        case SHN_COMMON: index = "COM"; break;
        case SHN_UNDEF:  index = "UND"; break;
        default:
            // printf( "%s\n", itoa( st_shndx ) );
            index = itoa( st_shndx );
    }
    strcpy( buff, index );
}

/*
 * Load file `fname` into memory
 * Pass the file descriptor to elf->fd
 */
bool load_file( const char *fname, ELF_t *elf )
{
    struct stat stat;
    
    if ( (elf->fd = open( fname, O_RDWR|O_APPEND,
          0x00 )) < 0x00 ){
        ERROR( errno, 0x01 );
    }
    // file info
    if ( fstat( elf->fd, &stat ) < 0 ||
            !S_ISREG( stat.st_mode ) ) {
        ERROR( errno, 0x01 );
    }

    elf->buff = (char *) mmap( NULL, stat.st_size,
                          PROT_READ|PROT_WRITE,
                          MAP_SHARED,
                          elf->fd,
                          0 );
    if ( elf->buff == (void *) (-1) ) {
        ERROR( errno, 0x01 );
    }
    elf->size = stat.st_size;
    elf->name = fname;
    return true;
}
/*
 * Verify that the target file is a valid one
 */
bool init_elf64( ELF_t *elf )
{
    Elf64_Ehdr *e_header = (Elf64_Ehdr *)  elf->buff;
    Elf64_Shdr *shdr     = (Elf64_Shdr *) (elf->buff + e_header->e_shoff);
    Elf64_Phdr *phdr     = (Elf64_Phdr *) (elf->buff + e_header->e_phoff);
    // is ELF ?
    if (  e_header->e_ident[EI_MAG0] != 0x7F ||
          e_header->e_ident[EI_MAG1] != 'E'  ||
          e_header->e_ident[EI_MAG2] != 'L'  ||
          e_header->e_ident[EI_MAG3] != 'F' )
    {
        ERROR( ELFORMAT, 0x01 );
    }
    // executable or shared object ?
    if ( e_header->e_type != ET_EXEC &&
         e_header->e_type != ET_DYN )
        ERROR( ELFTYPE, 0x01 );

    // is 64-bit format ?
    if ( e_header->e_ident[EI_CLASS] != 0x02 )
        ERROR( ELFBITS, 0x01 );
    
    elf->header = e_header;
    // get size of Section Header table
    if ( (elf->sht_size = elf64_get_sht_size( elf )) <= 0x00 )
        ERROR( ELFBITS, 0x01 );
    
    elf->arch      = elf64_arch( e_header );
    elf->shdr      = shdr;
    elf->phdr      = phdr;
    elf->striphdrs = 0x00;
    return true;
}

/* append new symbol to the list */
sym_list_t * add_item( Elf64_Sym *symbol, sym_list_t *list,
                         const char *strtab )
{
    sym_list_t *cursor;
    if ( !symbol ) {
        return list;
    }
    cursor = list;
    while ( cursor->next != NULL )
        cursor = cursor->next;

    if ( !(cursor->next = new_item( symbol, cursor, strtab )) ) {
        return NULL;
    }
    return list;
}
/*
 * Create a new symbol
 */
sym_list_t * new_item( Elf64_Sym *symbol, sym_list_t *current,
                       const char *strtab )
{
    sym_list_t *new_node;
    if ( !symbol || !current )
        return NULL;
    
    new_node = new sym_list_t[sizeof( sym_list_t )];
    if ( !new_node )
        return NULL;

    new_node->next = NULL;
    strcpy( current->name, strtab ? &strtab[symbol->st_name] : "" );
    current->size  = symbol->st_size;
    current->value = symbol->st_value;
    
    elf64_symbind( symbol->st_info,  current->bind  );
    elf64_symtype( symbol->st_info,  current->type  );
    elf64_symvis(  symbol->st_other, current->visib );
    elf64_symndx(  symbol->st_shndx, current->index );
    return new_node;
}
/*
 * Gather all symbols
 */
sym_list_t * elf64_get_symbols( ELF_t *elf, Symtab_t *symtb )
{
    sym_list_t *symlist;
    Elf64_Sym  *symtab, *ptr;
    char *strtab;
    
    symtab  = (Elf64_Sym *) (elf->buff + symtb->off);
    symlist = new sym_list_t[sizeof( sym_list_t )];
    if ( !symlist )
        return NULL;
    
    strtab = elf64_init_strtab( elf, symtb->stab );
    // initialize first element's next element
    // of list to point to NULL
    symlist->next = NULL;
    ptr = symtab;
    while ( symtb->n_ent ) {
        if ( add_item( ptr++, symlist, strtab ) == NULL )
            return NULL;
        symtb->n_ent--;
    }
    if ( strtab )
        delete[] strtab;
    return symlist;
}
/*
 * Print all symbols from symbol table
 */
void elf64_print_symbols( sym_list_t *symlist )
{
    char line[0x12c];
    uint16_t nsyms;
    sym_list_t *symbol, *next;
    
    nsyms  = 0x00;
    symbol = symlist;
    while ( symbol->next != NULL ) {
        sprintf(
            line,
            "   %2d: 0x%08x%08x   %-6lu %-8s %-7s  %-7s  %-3s  %s",
            nsyms++,
            (uint32_t) symbol->value >> 31 & 0xffffffff,
            (uint32_t) symbol->value       & 0xffffffff,
            symbol->size,
            symbol->type,
            symbol->bind,
            symbol->visib,
            symbol->index,
            symbol->name
        );
        std::cout << line << "\n";
        next = symbol->next;
        delete[] symbol;
        symbol = next;
    }
}
/* Get symbol table section header */
Elf64_Shdr * elf64_get_tbl_shdr( ELF_t *elf, uint16_t *ndx )
{
    short i;
    for ( i = 0x00 ; i < elf->header->e_shnum ; i++ ) {
        if ( elf->shdr[i].sh_type == SHT_SYMTAB ) {
            *ndx = i;
            return &elf->shdr[i];
        }
    } *ndx = 0x00; return NULL;
}

/* Get linked header of specified header */
Elf64_Shdr * elf64_get_link_hdr( ELF_t *elf, Elf64_Shdr *hdr,
                                 uint16_t *ndx )
{
    if ( hdr == NULL )
        return NULL;
    
    uint16_t nhdrs;
    nhdrs = elf->header->e_shnum;
    if ( hdr->sh_link <= 0x00 || hdr->sh_link >= nhdrs ){
        *ndx = 0x00;
        return NULL;
    }
    *ndx = hdr->sh_link;
    return &elf->shdr[hdr->sh_link];
}

/* Fill .strtab buffer with names */
char * elf64_init_strtab( ELF_t *elf, Strtab_t *stab )
{
    if ( !stab || stab->size <= 0x00 )
        return NULL;
    if ( stab->off <= 0x00 || stab->off >= (unsigned long) elf->size )
        return NULL;
    
    char *strtab;
    strtab = new char[stab->size];
    if ( !strtab )
        return NULL;
    memcpy( strtab, elf->buff + stab->off, stab->size );
    return strtab;
}

/* Get size of Section Header table */
uint32_t elf64_get_sht_size( ELF_t *elf )
{
    Elf64_Half shdrnum;
    Elf64_Half shsize;

    shdrnum = elf->header->e_shnum;
    shsize  = elf->header->e_shentsize;

    if ( shsize != ELF64BITS )
        ERROR( ELFSHSIZE, 0x00 );

    if ( shdrnum <= 0x00 )
        ERROR( ELFSHNUM, 0x00 );
    return (shdrnum * shsize);
}
/*
 * Check for the presence of .symtab and its associated .strtab
 * If not present (probably stripped), return -1, otherwise return its offset within the file
 */
bool elf64_find_symtab( ELF_t *elf, Symtab_t *symtb )
{
    Elf64_Shdr *symhdr;
    Elf64_Shdr *linkhdr;
    uint16_t ndx;

    if ( (symhdr = elf64_get_tbl_shdr( elf, &ndx )) == NULL )
        ERROR( ELFSYMTB, 0x01 );
    
    if ( (signed long) symhdr->sh_offset <= 0x00 ||
         (signed long) symhdr->sh_offset >= elf->size )
        ERROR( ELFSYMTBOFF, 0x01 );

    symtb->e_off  = ndx;
    symtb->off    = symhdr->sh_offset;
    symtb->size   = symhdr->sh_size;
    symtb->e_size = sizeof( Elf64_Sym );
    symtb->n_ent  = symtb->size / symtb->e_size;
    elf->striphdrs++;

    if ( (linkhdr = elf64_get_link_hdr( elf, symhdr, &ndx )) == NULL ){
        symtb->stab = NULL;
        return true;
    }
    symtb->stab = new Strtab_t[sizeof( Strtab_t )];
    if ( !symtb->stab ){
        symtb->stab = NULL;
        return true;
    }
    symtb->stab->e_off = ndx;
    symtb->stab->size  = linkhdr->sh_size;
    symtb->stab->off   = linkhdr->sh_offset;
    elf->striphdrs++;
    return true;
}

/* get a copy of a portion of the file */
void * elf64_get_block( ELF_t *elf, off64_t offset, size_t blocksize )
{
    char *c_buff = new char[blocksize];
    if ( !c_buff )
        return NULL;
    
    memset( c_buff, '\x00', blocksize );
    memcpy( c_buff, &elf->buff[offset], blocksize );
    return  (void *) c_buff;
}

/* update and resize elf file */
bool elf64_update( ELF_t *elf, off64_t offset, const char *buff, size_t len )
{
    if ( buff )
        memcpy( &elf->buff[offset], buff, len );

    msync( &elf->buff[0],    elf->size, MS_SYNC );
    if ( ftruncate( elf->fd, elf->size ) < 0x00 )
        ERROR( errno, 0x01 );
    return true;
}

/* update .shstrtab's Section Headers index */
void elf64_update_shstrndx( ELF_t *elf, Symtab_t *symtb )
{
    uint16_t *shstrndx;

    shstrndx = &(elf->header->e_shstrndx);
    if ( *shstrndx > symtb->e_off )
        (*shstrndx)--;
        
    if ( symtb->stab ) {
        if ( *shstrndx > symtb->stab->e_off )
            (*shstrndx)--;
    }
}
/*
 * remove a portion of a buffer
 */
void elf64_remove_at_offset( char *buff, size_t bsize, off64_t offset, size_t len )
{
    memmove( &buff[offset], &buff[offset + len], bsize - (offset + len) );
}

/* zero fill .symtab and .strtab names in .shstrtab */
void remove_sh_names( char *buff, size_t bsize )
{
    register uint16_t idx = 0;
    do {
        if ( buff[idx++] == '.' ) {
            if ( memcmp( &buff[idx - 1], ".symtab", 0x07 ) == 0x00 ||
                 memcmp( &buff[idx - 1], ".strtab", 0x07 ) == 0x00 ) {
                 memset( &buff[idx - 1],    '\x00', 0x07 );
            }
        }
    } while ( idx < bsize );
}
/* strip .symtab and .strtab headers */
bool elf64_strip_headers( ELF_t *elf, Symtab_t *symtb )
{
    char    *block;
    off64_t  e_shoff;
    uint32_t blocksize;
    size_t   bufsize;

    blocksize = elf->sht_size;
    bufsize   = elf->sht_size - (elf->striphdrs * entry_size);
    e_shoff   = elf->header->e_shoff;

    // get a copy of Section Headers table
    if ( !(block = (char *) elf64_get_block( elf, e_shoff, blocksize )) )
        return false;
    
    // remove .symtab section header
    elf64_remove_at_offset(
        block,
        blocksize,
        symtb->e_off * entry_size,
        entry_size
    );
    if ( symtb->stab ) {
        if ( symtb->stab->e_off > symtb->e_off )
            symtb->stab->e_off--;

        // remove .strtab section header
        elf64_remove_at_offset(
            block,
            blocksize,
            symtb->stab->e_off * entry_size,
            entry_size
        );
    }
    elf->header->e_shnum -= elf->striphdrs;
    elf->size -= elf->striphdrs * entry_size;

    if ( elf64_update( elf, e_shoff, block, bufsize ) == false )
        return false;

    delete[] block;
    elf64_update_shstrndx( elf, symtb );
    return true;
}

/* get a copy of Section Headers table with modified sections' file offsets
 * (modified if necessary)
 */
Elf64_Shdr * elf64_get_mod_sh_hdrs_off( ELF_t *elf, Symtab_t *symtb )
{
    size_t      bufsize;
    size_t      rm_size;
    Elf64_Shdr *headers;

    rm_size = 0;
    bufsize = elf->header->e_shnum * entry_size;
    headers = (Elf64_Shdr *) elf64_get_block( elf, elf->header->e_shoff, bufsize );
    
    if ( headers == NULL )
        return NULL;

    for( uint16_t i = 0 ; i < elf->header->e_shnum ; i++ ) {
        if ( headers[i].sh_offset > symtb->off )
             rm_size += symtb->size;

        if ( symtb->stab && headers[i].sh_offset > symtb->stab->off ) {
            rm_size += symtb->stab->size;
        }
        headers[i].sh_offset -= rm_size;
        rm_size = 0;
    }
    return headers;
}
/*
 * strip .symtab and .strtab sections
 */
bool elf64_strip_sections( ELF_t *elf, Symtab_t *symtb )
{
    off64_t     e_shoff;
    size_t      rm_size;
    uint32_t    blocksize;
    Elf64_Shdr *headers;
    Elf64_Shdr *shstr;

    rm_size   = 0x00;
    blocksize = elf->sht_size;

    if ( (headers = elf64_get_mod_sh_hdrs_off( elf, symtb )) == NULL )
        return false;

    // remove .symtab section
    elf64_remove_at_offset(
        elf->buff,
        elf->size,
        symtb->off,
        symtb->size
    );
    rm_size += symtb->size;
    
    if ( symtb->stab ) {
        if ( symtb->stab->off  > symtb->off ) {
             symtb->stab->off -= symtb->size;
        }
        // remove .strtab section (if present)
        elf64_remove_at_offset(
            elf->buff,
            elf->size,
            symtb->stab->off,
            symtb->stab->size
        );
        rm_size += symtb->stab->size;
    }

    shstr                 = &headers[elf->header->e_shstrndx];
    elf->header->e_shoff -= rm_size;
    e_shoff               = elf->header->e_shoff;
    elf->size            -= rm_size;
    remove_sh_names( &elf->buff[shstr->sh_offset], shstr->sh_size );

    if ( elf64_update( elf, e_shoff, (char *) headers, blocksize ) == false )
        return false;

    delete[] headers;
    return true;
}
/*
 * Strip and optionally dump symbol table
 */
bool elf64_symstrip( ELF_t *elf, const ST_Opts *opts )
{
    Symtab_t    symtb;
    sym_list_t *symlist;
    // check for the presence of a symbol table
    if ( elf64_find_symtab( elf, &symtb ) == false ) {
        SHUT( elf );
        return false;
    }
    
    if ( opts->dump ) {
        if ( (symlist = elf64_get_symbols( elf, &symtb )) == NULL )
            puts( errbuf );
        else
            elf64_print_symbols( symlist );
    }
    if ( opts->strip ){
        if ( elf64_strip_headers( elf, &symtb ) == false ) {
            if ( strlen( errbuf ) > 0 )
                puts( errbuf );
        }
        if ( elf64_strip_sections( elf, &symtb ) == false ) {
            if ( strlen( errbuf ) > 0 )
                puts( errbuf );
        }
    }
    SHUT( elf );
    return true;
}

int main( int argc, char **argv )
{
    int opt;
    char *file;
    ELF_t elf;
    ST_Opts opts;

    opts.dump  = 0;
    opts.strip = 0;
    file       = NULL;

    while ( (opt = getopt( argc, argv, "f:ds" )) != -1 )
    {
        switch ( opt ) {
            case 'f':
                file = optarg;
                break;
            case 'd':
                opts.dump = 1;
                break;
            case 's':
                opts.strip = 1;
                break;
            default:
                __usage( argv[0] );
        }
    }

    if ( !file || (opts.dump && opts.strip) || (!opts.strip && !opts.dump) )
        __usage( argv[0] );

    if ( load_file( file, &elf ) == false ){
        if ( elf.fd ) {
            close( elf.fd );
        }
        _FATAL( errbuf );
    }

    if ( init_elf64( &elf ) == false )
        _FATAL( errbuf );

    std::cout << "File architecture: " << elf.arch << "\n";
    if ( elf64_symstrip( &elf, &opts ) == false )
        _FATAL( errbuf );

    return 0;
}

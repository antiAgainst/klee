//===-- fd_init.c ---------------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64
#include "fd.h"
#include <klee/klee.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <elf.h>


exe_file_system_t __exe_fs;

/* NOTE: It is important that these are statically initialized
   correctly, since things that run before main may hit them given the
   current way things are linked. */

/* XXX Technically these flags are initialized w.o.r. to the
   environment we are actually running in. We could patch them in
   klee_init_fds, but we still have the problem that uclibc calls
   prior to main will get the wrong data. Not such a big deal since we
   mostly care about sym case anyway. */


exe_sym_env_t __exe_env = { 
  {{ 0, eOpen | eReadable, 0, 0}, 
   { 1, eOpen | eWriteable, 0, 0}, 
   { 2, eOpen | eWriteable, 0, 0}},
  022,
  0,
  0
};

static void __create_new_normalfile(exe_disk_file_t *dfile, unsigned size,
                                    const char *name, struct stat64 *defaults) {
  struct stat64 *s = malloc(sizeof(*s));
  const char *sp;
  char sname[64];
  for (sp=name; *sp; ++sp)
    sname[sp-name] = *sp;
  memcpy(&sname[sp-name], "-stat", 6);

  assert(size);

  dfile->size = size;
  dfile->contents = malloc(dfile->size);
  klee_make_symbolic(dfile->contents, dfile->size, name);
  
  klee_make_symbolic(s, sizeof(*s), sname);

  /* For broken tests */
  if (!klee_is_symbolic(s->st_ino) && 
      (s->st_ino & 0x7FFFFFFF) == 0)
    s->st_ino = defaults->st_ino;
  
  /* Important since we copy this out through getdents, and readdir
     will otherwise skip this entry. For same reason need to make sure
     it fits in low bits. */
  klee_assume((s->st_ino & 0x7FFFFFFF) != 0);

  /* uclibc opendir uses this as its buffer size, try to keep
     reasonable. */
  klee_assume((s->st_blksize & ~0xFFFF) == 0);

  klee_prefer_cex(s, !(s->st_mode & ~(S_IFMT | 0777)));
  klee_prefer_cex(s, s->st_dev == defaults->st_dev);
  klee_prefer_cex(s, s->st_rdev == defaults->st_rdev);
  klee_prefer_cex(s, (s->st_mode&0700) == 0600);
  klee_prefer_cex(s, (s->st_mode&0070) == 0020);
  klee_prefer_cex(s, (s->st_mode&0007) == 0002);
  klee_prefer_cex(s, (s->st_mode&S_IFMT) == S_IFREG);
  klee_prefer_cex(s, s->st_nlink == 1);
  klee_prefer_cex(s, s->st_uid == defaults->st_uid);
  klee_prefer_cex(s, s->st_gid == defaults->st_gid);
  klee_prefer_cex(s, s->st_blksize == 4096);
  klee_prefer_cex(s, s->st_atime == defaults->st_atime);
  klee_prefer_cex(s, s->st_mtime == defaults->st_mtime);
  klee_prefer_cex(s, s->st_ctime == defaults->st_ctime);

  s->st_size = dfile->size;
  s->st_blocks = 8;
  dfile->stat = s;
}

static void __create_new_elffile(exe_disk_file_t *dfile, unsigned size,
                                 const char *name, struct stat64 *defaults) {
  struct stat64 *s = malloc(sizeof(*s));
  const char *sp;
  char sname[64];
  for (sp=name; *sp; ++sp)
    sname[sp-name] = *sp;
  memcpy(&sname[sp-name], "-stat", 6);

  assert(size);

  dfile->size = size;
  dfile->contents = malloc(dfile->size);
  klee_make_symbolic(dfile->contents, dfile->size, name);

  /* we just assume this is an 64-bit ELF file now */
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *) dfile->contents;

  /* first determine the class: 32-bit or 64-bit */
  klee_assume(ehdr->e_ident[EI_CLASS] < ELFCLASSNUM);
  //klee_assume(
  //    (ehdr->e_ident[EI_CLASS] == ELFCLASS32) |
  //    (ehdr->e_ident[EI_CLASS] == ELFCLASS64)
  //);

  unsigned secsz = 8U;    // size of each section
  unsigned shnum = 5U;    // number of section headers
  unsigned phnum = 1U;    // number of program headers
  unsigned symtabnum = 2U; // number of symbol table entries
  unsigned dynsecnum = 2U; // number of dynamic section entries

  if (ehdr->e_ident[EI_CLASS] == ELFCLASS64) {
    unsigned ehsize = sizeof(Elf64_Ehdr);

    /* --- ELF header --- */

    /* e_ident[] */
    ehdr->e_ident[EI_MAG0] = ELFMAG0;
    ehdr->e_ident[EI_MAG1] = ELFMAG1;
    ehdr->e_ident[EI_MAG2] = ELFMAG2;
    ehdr->e_ident[EI_MAG3] = ELFMAG3;
    klee_assume(ehdr->e_ident[EI_CLASS] <= ELFCLASSNUM);
    klee_assume(ehdr->e_ident[EI_DATA] <= ELFDATANUM);
    klee_assume(
        (ehdr->e_ident[EI_VERSION] == EV_NONE) |
        (ehdr->e_ident[EI_VERSION] == EV_CURRENT)
    );
    klee_assume(
      (ehdr->e_ident[EI_OSABI] == ELFOSABI_NONE) |
      (ehdr->e_ident[EI_OSABI] == ELFOSABI_SYSV) |
      (ehdr->e_ident[EI_OSABI] == ELFOSABI_HPUX) |
      (ehdr->e_ident[EI_OSABI] == ELFOSABI_NETBSD) |
      (ehdr->e_ident[EI_OSABI] == ELFOSABI_GNU) |
      (ehdr->e_ident[EI_OSABI] == ELFOSABI_LINUX) |
      (ehdr->e_ident[EI_OSABI] == ELFOSABI_SOLARIS) |
      (ehdr->e_ident[EI_OSABI] == ELFOSABI_AIX) |
      (ehdr->e_ident[EI_OSABI] == ELFOSABI_IRIX) |
      (ehdr->e_ident[EI_OSABI] == ELFOSABI_FREEBSD) |
      (ehdr->e_ident[EI_OSABI] == ELFOSABI_TRU64) |
      (ehdr->e_ident[EI_OSABI] == ELFOSABI_MODESTO) |
      (ehdr->e_ident[EI_OSABI] == ELFOSABI_OPENBSD) |
      (ehdr->e_ident[EI_OSABI] == ELFOSABI_ARM_AEABI) |
      (ehdr->e_ident[EI_OSABI] == ELFOSABI_ARM) |
      (ehdr->e_ident[EI_OSABI] == ELFOSABI_STANDALONE)
    );

    /* e_type, e_machine, e_version */
    klee_assume(
        (ehdr->e_type <= ET_CORE) |
        ((ehdr->e_type >= ET_LOOS) & (ehdr->e_type <= ET_HIOS)) |
        ((ehdr->e_type >= ET_LOPROC) & (ehdr->e_type < ET_HIPROC))
    );
    klee_assume(ehdr->e_machine <= EM_NUM); /* INCOMPLETE */
    klee_assume(ehdr->e_version <= EV_NUM);
    /* e_entry */ /* MISSING */
    /* e_phoff, e_shoff */ /* SEE BELOW */
    /* e_flags */ /* MISSING */
    /* e_ehsize */
    ehdr->e_ehsize = ehsize;
    /* e_phentsize, e_phnum */
    ehdr->e_phentsize = sizeof(Elf64_Phdr);
    ehdr->e_phnum = phnum;
    /* e_shentsize, e_shnum */
    ehdr->e_shentsize = sizeof(Elf64_Shdr);
    ehdr->e_shnum = shnum;
    /* e_shstrndx */
    ehdr->e_shstrndx = 1U; /* FORCE */

    unsigned offset = ehsize + shnum * sizeof(Elf64_Shdr);

    /* e_shoff, e_phoff */
    ehdr->e_shoff = ehsize;
    ehdr->e_phoff = offset;

    /* section header table */
    Elf64_Shdr *shdrt = (Elf64_Shdr *) ((char *)dfile->contents + ehsize);
    Elf64_Shdr *shdr;

    /* program header table */
    Elf64_Phdr *phdrt = (Elf64_Phdr *) ((char *)dfile->contents + offset);
    Elf64_Phdr *phdr;

    /* the current available offset for section contents */
    offset += phnum * sizeof(Elf64_Phdr);

    unsigned section_start = offset;

    /* --- section header table --- */

    /* 0: null section */
    shdr = shdrt;
    shdr->sh_type = SHT_NULL;
    shdr->sh_size = 0U;

    /* 1: section header string table */
    shdr = shdrt + 1;
    shdr->sh_type = SHT_STRTAB;
    shdr->sh_offset = offset;
    shdr->sh_size = secsz;
    offset += secsz;

    /* 2: symbol table */
    shdr = shdrt + 2;
    shdr->sh_type = SHT_SYMTAB;
    shdr->sh_offset = offset;
    shdr->sh_size = symtabnum * sizeof(Elf64_Sym);
    offset += symtabnum * sizeof(Elf64_Sym);
    shdr->sh_entsize = sizeof(Elf64_Sym);

    /* 3: dynamic section */
    shdr = shdrt + 3;
    shdr->sh_type = SHT_DYNAMIC;
    shdr->sh_offset = offset;
    shdr->sh_size = dynsecnum * sizeof(Elf64_Dyn);
    offset += dynsecnum * sizeof(Elf64_Dyn);
    shdr->sh_entsize = sizeof(Elf64_Dyn);

    /* 4: random section */
    shdr = shdrt + 4;
    /* sh_name */ /* MISSING */
    /* sh_type */
    klee_assume(
        (shdr->sh_type < SHT_NUM) |
        ((shdr->sh_type >= SHT_LOOS) & (shdr->sh_type <= SHT_HIOS)) |
        ((shdr->sh_type >= SHT_LOPROC) & (shdr->sh_type <= SHT_HIPROC)) |
        ((shdr->sh_type >= SHT_LOUSER) & (shdr->sh_type <= SHT_HIUSER))
    );
    /* sh_flags, sh_addr */ /* MISSING */
    /* sh_offset */
    shdr->sh_offset = offset;
    /* sh_size */
    shdr->sh_size = secsz;
    offset += secsz;
    /* sh_link, sh_info */ /* MISSING */
    /* sh_addralign, sh_entsize */ /* MISSING */

    unsigned section_end = offset;

    /* --- program header table --- */

    phdr = phdrt;
    /* p_type */
    klee_assume(
        (phdr->p_type < PT_NUM) |
        ((phdr->p_type >= PT_LOOS) & (phdr->p_type <= PT_HIOS)) |
        ((phdr->p_type >= PT_LOPROC) & (phdr->p_type <= PT_HIPROC))
    );
    /* p_flags */ /* MISSING */
    /* p_offset */
    klee_assume(phdr->p_offset >= section_start);
    klee_assume(phdr->p_offset < section_end);
    /* p_vaddr, p_paddr */ /* MISSING */
    /* p_filesz, p_memsz */ /* MISSING */
    /* p_align */ /* MISSING */

    /* make sure we don't have more bytes than the file allows */
    klee_assume(offset <= size);
  } else if (ehdr->e_ident[EI_CLASS] == ELFCLASS32) {
    unsigned ehsize = sizeof(Elf32_Ehdr);

    /* type cast to 32-bit layout */
    Elf32_Ehdr *ehdr32 = (Elf32_Ehdr *) dfile->contents;

    /* --- ELF header --- */

    /* e_ident[] */
    ehdr32->e_ident[EI_MAG0] = ELFMAG0;
    ehdr32->e_ident[EI_MAG1] = ELFMAG1;
    ehdr32->e_ident[EI_MAG2] = ELFMAG2;
    ehdr32->e_ident[EI_MAG3] = ELFMAG3;
    klee_assume(ehdr32->e_ident[EI_CLASS] <= ELFCLASSNUM);
    klee_assume(ehdr32->e_ident[EI_DATA] <= ELFDATANUM);
    klee_assume(
      (ehdr32->e_ident[EI_VERSION] == EV_NONE) |
      (ehdr32->e_ident[EI_VERSION] == EV_CURRENT)
    );
    klee_assume(
      (ehdr32->e_ident[EI_OSABI] == ELFOSABI_NONE) |
      (ehdr32->e_ident[EI_OSABI] == ELFOSABI_SYSV) |
      (ehdr32->e_ident[EI_OSABI] == ELFOSABI_HPUX) |
      (ehdr32->e_ident[EI_OSABI] == ELFOSABI_NETBSD) |
      (ehdr32->e_ident[EI_OSABI] == ELFOSABI_GNU) |
      (ehdr32->e_ident[EI_OSABI] == ELFOSABI_LINUX) |
      (ehdr32->e_ident[EI_OSABI] == ELFOSABI_SOLARIS) |
      (ehdr32->e_ident[EI_OSABI] == ELFOSABI_AIX) |
      (ehdr32->e_ident[EI_OSABI] == ELFOSABI_IRIX) |
      (ehdr32->e_ident[EI_OSABI] == ELFOSABI_FREEBSD) |
      (ehdr32->e_ident[EI_OSABI] == ELFOSABI_TRU64) |
      (ehdr32->e_ident[EI_OSABI] == ELFOSABI_MODESTO) |
      (ehdr32->e_ident[EI_OSABI] == ELFOSABI_OPENBSD) |
      (ehdr32->e_ident[EI_OSABI] == ELFOSABI_ARM_AEABI) |
      (ehdr32->e_ident[EI_OSABI] == ELFOSABI_ARM) |
      (ehdr32->e_ident[EI_OSABI] == ELFOSABI_STANDALONE)
    );

    /* e_type, e_machine, e_version */
    klee_assume(
        (ehdr32->e_type <= ET_CORE) |
        ((ehdr32->e_type >= ET_LOOS) & (ehdr32->e_type <= ET_HIOS)) |
        ((ehdr32->e_type >= ET_LOPROC) & (ehdr32->e_type < ET_HIPROC))
    );
    klee_assume(ehdr32->e_machine <= EM_NUM); /* INCOMPLETE */
    klee_assume(ehdr32->e_version <= EV_NUM);
    /* e_entry */ /* MISSING */
    /* e_phoff, e_shoff */ /* SEE BELOW */
    /* e_flags */ /* MISSING */
    /* e_ehsize */
    ehdr32->e_ehsize = ehsize;
    /* e_phentsize, e_phnum */
    ehdr32->e_phentsize = sizeof(Elf32_Phdr);
    ehdr32->e_phnum = phnum;
    /* e_shentsize, e_shnum */
    ehdr32->e_shentsize = sizeof(Elf32_Shdr);
    ehdr32->e_shnum = shnum;
    /* e_shstrndx */
    ehdr32->e_shstrndx = 1U; /* FORCE */

    unsigned offset = ehsize + shnum * sizeof(Elf32_Shdr);

    /* e_shoff, e_phoff */
    ehdr32->e_shoff = ehsize;
    ehdr32->e_phoff = offset;

    /* section header table */
    Elf32_Shdr *shdrt = (Elf32_Shdr *) ((char *)dfile->contents + ehsize);
    Elf32_Shdr *shdr;

    /* program header table */
    Elf32_Phdr *phdrt = (Elf32_Phdr *) ((char *)dfile->contents + offset);
    Elf32_Phdr *phdr;

    /* the current available offset for section contents */
    offset += phnum * sizeof(Elf32_Phdr);

    unsigned section_start = offset;

    /* --- section header table --- */

    /* 0: null section */
    shdr = shdrt;
    shdr->sh_type = SHT_NULL;
    shdr->sh_size = 0U;

    /* 1: section header string table */
    shdr = shdrt + 1;
    shdr->sh_type = SHT_STRTAB;
    shdr->sh_offset = offset;
    shdr->sh_size = secsz;
    offset += secsz;

    /* 2: symbol table */
    shdr = shdrt + 2;
    shdr->sh_type = SHT_SYMTAB;
    shdr->sh_offset = offset;
    shdr->sh_size = symtabnum * sizeof(Elf32_Sym);
    offset += symtabnum * sizeof(Elf32_Sym);
    shdr->sh_entsize = sizeof(Elf32_Sym);

    /* 3: dynamic section */
    shdr = shdrt + 3;
    shdr->sh_type = SHT_DYNAMIC;
    shdr->sh_offset = offset;
    shdr->sh_size = dynsecnum * sizeof(Elf32_Dyn);
    offset += dynsecnum * sizeof(Elf32_Dyn);
    shdr->sh_entsize = sizeof(Elf32_Dyn);

    /* 4: random section */
    shdr = shdrt + 4;
    /* sh_name */ /* MISSING */
    /* sh_type */
    klee_assume(
        (shdr->sh_type < SHT_NUM) |
        ((shdr->sh_type >= SHT_LOOS) & (shdr->sh_type <= SHT_HIOS)) |
        ((shdr->sh_type >= SHT_LOPROC) & (shdr->sh_type <= SHT_HIPROC)) |
        ((shdr->sh_type >= SHT_LOUSER) & (shdr->sh_type <= SHT_HIUSER))
    );
    /* sh_flags, sh_addr */ /* MISSING */
    /* sh_offset */
    shdr->sh_offset = offset;
    /* sh_size */
    shdr->sh_size = secsz;
    offset += secsz;
    /* sh_link, sh_info */ /* MISSING */
    /* sh_addralign, sh_entsize */ /* MISSING */

    unsigned section_end = offset;

    /* --- program header table --- */

    phdr = phdrt;
    /* p_type */
    klee_assume(
        (phdr->p_type < PT_NUM) |
        ((phdr->p_type >= PT_LOOS) & (phdr->p_type <= PT_HIOS)) |
        ((phdr->p_type >= PT_LOPROC) & (phdr->p_type <= PT_HIPROC))
    );
    /* p_flags */ /* MISSING */
    /* p_offset */
    klee_assume(phdr->p_offset >= section_start);
    klee_assume(phdr->p_offset < section_end);
    /* p_vaddr, p_paddr */ /* MISSING */
    /* p_filesz, p_memsz */ /* MISSING */
    /* p_align */ /* MISSING */

    /* make sure we don't have more bytes than the file allows */
    klee_assume(offset <= size);
  }

  klee_make_symbolic(s, sizeof(*s), sname);

  /* For broken tests */
  if (!klee_is_symbolic(s->st_ino) &&
      (s->st_ino & 0x7FFFFFFF) == 0)
    s->st_ino = defaults->st_ino;

  /* Important since we copy this out through getdents, and readdir
     will otherwise skip this entry. For same reason need to make sure
     it fits in low bits. */
  klee_assume((s->st_ino & 0x7FFFFFFF) != 0);

  /* uclibc opendir uses this as its buffer size, try to keep
     reasonable. */
  klee_assume((s->st_blksize & ~0xFFFF) == 0);

  klee_prefer_cex(s, !(s->st_mode & ~(S_IFMT | 0777)));
  klee_prefer_cex(s, s->st_dev == defaults->st_dev);
  klee_prefer_cex(s, s->st_rdev == defaults->st_rdev);
  klee_prefer_cex(s, (s->st_mode&0700) == 0600);
  klee_prefer_cex(s, (s->st_mode&0070) == 0020);
  klee_prefer_cex(s, (s->st_mode&0007) == 0002);
  klee_prefer_cex(s, (s->st_mode&S_IFMT) == S_IFREG);
  klee_prefer_cex(s, s->st_nlink == 1);
  klee_prefer_cex(s, s->st_uid == defaults->st_uid);
  klee_prefer_cex(s, s->st_gid == defaults->st_gid);
  klee_prefer_cex(s, s->st_blksize == 4096);
  klee_prefer_cex(s, s->st_atime == defaults->st_atime);
  klee_prefer_cex(s, s->st_mtime == defaults->st_mtime);
  klee_prefer_cex(s, s->st_ctime == defaults->st_ctime);

  s->st_size = dfile->size;
  s->st_blocks = 8;
  dfile->stat = s;
}

static unsigned __sym_uint32(const char *name) {
  unsigned x;
  klee_make_symbolic(&x, sizeof x, name);
  return x;
}

/* n_nfiles: number of symbolic normal files, excluding stdin
   nfile_length: size in bytes of each symbolic normal file, including stdin
   n_efiles: number of symbolic elf files
   efile_length: size in bytes of each symbolic elf file */
void klee_init_fds(unsigned n_nfiles, unsigned nfile_length,
                   unsigned n_efiles, unsigned efile_length) {
  unsigned k;
  char name[7] = "?-data";
  struct stat64 s;

  stat64(".", &s);

  unsigned n_files = n_nfiles + n_efiles;
  __exe_fs.n_sym_files = n_files;
  __exe_fs.sym_files = malloc(sizeof(*__exe_fs.sym_files) * n_files);
  for (k=0; k < n_nfiles; k++) {
    name[0] = 'A' + k;
    __create_new_normalfile(&__exe_fs.sym_files[k], nfile_length, name, &s);
  }
  for (; k < n_files; k++) {
    name[0] = 'A' + k;
    __create_new_elffile(&__exe_fs.sym_files[k], efile_length, name, &s);
  }
}
  
/* file_length: size in bytes of stdin
   sym_stdout_flag: 1 if stdout should be symbolic, 0 otherwise
   save_all_writes_flag: 1 if all writes are executed as expected, 0 if
                         writes past the initial file size are discarded
			 (file offset is always incremented)
   max_failures: maximum number of system call failures */
void klee_init_std_fds(unsigned file_length, int sym_stdout_flag,
                       int save_all_writes_flag, unsigned max_failures) {
  struct stat64 s;
  stat64(".", &s);
  /* setting symbolic stdin */
  if (file_length) {
    __exe_fs.sym_stdin = malloc(sizeof(*__exe_fs.sym_stdin));
    __create_new_normalfile(__exe_fs.sym_stdin, file_length, "stdin", &s);
    __exe_env.fds[0].dfile = __exe_fs.sym_stdin;
  }
  else __exe_fs.sym_stdin = NULL;

  __exe_fs.max_failures = max_failures;
  if (__exe_fs.max_failures) {
    __exe_fs.read_fail = malloc(sizeof(*__exe_fs.read_fail));
    __exe_fs.write_fail = malloc(sizeof(*__exe_fs.write_fail));
    __exe_fs.close_fail = malloc(sizeof(*__exe_fs.close_fail));
    __exe_fs.ftruncate_fail = malloc(sizeof(*__exe_fs.ftruncate_fail));
    __exe_fs.getcwd_fail = malloc(sizeof(*__exe_fs.getcwd_fail));

    klee_make_symbolic(__exe_fs.read_fail, sizeof(*__exe_fs.read_fail), "read_fail");
    klee_make_symbolic(__exe_fs.write_fail, sizeof(*__exe_fs.write_fail), "write_fail");
    klee_make_symbolic(__exe_fs.close_fail, sizeof(*__exe_fs.close_fail), "close_fail");
    klee_make_symbolic(__exe_fs.ftruncate_fail, sizeof(*__exe_fs.ftruncate_fail), "ftruncate_fail");
    klee_make_symbolic(__exe_fs.getcwd_fail, sizeof(*__exe_fs.getcwd_fail), "getcwd_fail");
  }

  /* setting symbolic stdout */
  if (sym_stdout_flag) {
    __exe_fs.sym_stdout = malloc(sizeof(*__exe_fs.sym_stdout));
    __create_new_normalfile(__exe_fs.sym_stdout, 1024, "stdout", &s);
    __exe_env.fds[1].dfile = __exe_fs.sym_stdout;
    __exe_fs.stdout_writes = 0;
  }
  else __exe_fs.sym_stdout = NULL;
  
  __exe_env.save_all_writes = save_all_writes_flag;
  __exe_env.version = __sym_uint32("model_version");
  klee_assume(__exe_env.version == 1);
}

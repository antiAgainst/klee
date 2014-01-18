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

  /* elf header, section header, program segment header size */
  unsigned ehsize, shsize, phsize;
  unsigned i;

  /* elf header */
  /* we just assume this is an 64-bit ELF file now */
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *) dfile->contents;

  /* first determine the class: 32-bit or 64-bit */
  klee_assume(ehdr->e_ident[EI_CLASS] < ELFCLASSNUM);

/* klee_assume()s for e_ident in elf header, excluding EI_CLASS */
#define ELF_ASSUME_EHDR_IDENT(ehdr) \
  do { \
    klee_assume(ehdr->e_ident[EI_MAG0] == ELFMAG0); \
    klee_assume(ehdr->e_ident[EI_MAG1] == ELFMAG1); \
    klee_assume(ehdr->e_ident[EI_MAG2] == ELFMAG2); \
    klee_assume(ehdr->e_ident[EI_MAG3] == ELFMAG3);\
    klee_assume(ehdr->e_ident[EI_DATA] < ELFDATANUM); \
    klee_assume(ehdr->e_ident[EI_VERSION] == EV_CURRENT); \
    /* klee_assume(ehdr->e_ident[EI_OSABI] >= ELFOSABI_NONE); */ \
    klee_assume((ehdr->e_ident[EI_OSABI] <= ELFOSABI_GNU) | \
                ((ehdr->e_ident[EI_OSABI] >= ELFOSABI_SOLARIS) & \
                 (ehdr->e_ident[EI_OSABI] <= ELFOSABI_OPENBSD)) | \
                (ehdr->e_ident[EI_OSABI] == ELFOSABI_ARM_AEABI) | \
                (ehdr->e_ident[EI_OSABI] == ELFOSABI_ARM) | \
                (ehdr->e_ident[EI_OSABI] == ELFOSABI_STANDALONE)); \
    /* EI_ABIVERSION, what to put here? */ \
    /* EI_PAD, not used from here */ \
  } while (0)

/* klee_assume()s for e_type, e_machine, e_version in elf header */
#define ELF_ASSUME_EHDR_TYPE_MACHINE_VERSION(ptr) \
  do { \
    klee_assume(ptr->e_type < ET_NUM); \
    klee_assume(ptr->e_machine < EM_NUM); \
    klee_assume(ptr->e_version < EV_NUM); \
  } while (0)

/* klee_assume()s for program segment header table in elf header */
#define ELF_ASSUME_EHDR_PHT(ptr, size, min, max) \
  do { \
    klee_assume(ptr->e_phentsize == size); \
    /* klee_assume(ptr->e_phnum >= min); */ \
    klee_assume(ptr->e_phnum <= max); \
  } while (0)

/* klee_assume()s for section header table in elf header */
#define ELF_ASSUME_EHDR_SHT(ptr, size, min, max) \
  do { \
    klee_assume(ptr->e_shentsize == size); \
    klee_assume(ptr->e_shnum >= min); \
    klee_assume(ptr->e_shnum <= max); \
  } while (0)

/* klee_assume()s for section header table */
#define ELF_ASSUME_SHT(ehdr, shdrt, shdr, size, offset) \
  do { \
    /* 0: null section */ \
    shdr = shdrt; \
    klee_assume(shdr->sh_type == SHT_NULL); \
    klee_assume(shdr->sh_size == 0U); \
    /* 1: section header string table */ \
    shdr = shdrt + 1; \
    klee_assume(shdr->sh_type == SHT_STRTAB); \
    klee_assume(shdr->sh_offset == offset); \
    klee_assume(shdr->sh_size == size); \
    offset += shdr->sh_size; \
    /* other sections */ \
    for (i = 2; i < ehdr->e_shnum; ++i) { \
      /* section header */ \
      shdr = shdrt + i; \
      /* sh_name */ \
      /* sh_type */ \
      klee_assume(shdr->sh_type > SHT_NULL); \
      klee_assume(shdr->sh_type < SHT_NUM); \
      /* sh_flags */ \
      /* sh_addr */ \
      /* sh_offset */ \
      klee_assume(shdr->sh_offset == offset); \
      /* sh_size */ \
      klee_assume(shdr->sh_size == size); \
      offset += shdr->sh_size; \
      /* sh_link */ \
      /* sh_info */ \
      /* sh_addralign */ \
      /* sh_entsize */ \
    } \
  } while (0)

/* klee_assume()s for program segment header table */
#define ELF_ASSUME_PHT(ehdr, phdrt, phdr, secstart, secend) \
  for (i = 0; i < ehdr->e_phnum; ++i) { \
    /* program segment header */ \
    phdr = phdrt + i; \
    /* p_type */ \
    klee_assume(phdr->p_type < PT_NUM); \
    /* p_flags */ \
    /* p_offset */ \
    klee_assume(phdr->p_offset >= secstart); \
    klee_assume(phdr->p_offset < secend); \
    /* p_vaddr */ \
    /* p_paddr */ \
    /* p_filesz */ \
    /* p_memsz */ \
    /* p_align */ \
  }

  if (ehdr->e_ident[EI_CLASS] == ELFCLASS64) {
    ehsize = sizeof(Elf64_Ehdr);
    shsize = sizeof(Elf64_Shdr);
    phsize = sizeof(Elf64_Phdr);

    ELF_ASSUME_EHDR_IDENT(ehdr);
    ELF_ASSUME_EHDR_TYPE_MACHINE_VERSION(ehdr);
    /* e_entry, what to put here? */
    /* e_shoff */
    klee_assume(ehdr->e_shoff == ehsize);
    /* e_flags, what to put here? */
    /* e_ehsize, size of elf header */
    klee_assume(ehdr->e_ehsize == ehsize);
    ELF_ASSUME_EHDR_PHT(ehdr, phsize, 0U, 3U);
    ELF_ASSUME_EHDR_SHT(ehdr, shsize, 2U, 5U);
    /* e_shstrndx, we force it to be at index 1 */
    klee_assume(ehdr->e_shstrndx == 1U);

    /* section header table */
    Elf64_Shdr *shdrt = (Elf64_Shdr *) ((char *)dfile->contents + ehdr->e_shoff);
    Elf64_Shdr *shdr;

    /* the current available offset for real sections */
    unsigned offset = ehdr->e_shoff + ehdr->e_shnum * shsize;
    unsigned secstart = offset;

    ELF_ASSUME_SHT(ehdr, shdrt, shdr, 32U, offset);

    /* now offset is the byte after all real sections */
    unsigned secend = offset;
    /* make sure we don't have more bytes than the file allows */
    klee_assume(offset <= size);

    if (ehdr->e_phnum) {
      /* e_phoff, just let it appear after the sections */
      klee_assume(ehdr->e_phoff == offset);
      /* make sure we don't have more bytes than the file allows */
      klee_assume(ehdr->e_phoff + ehdr->e_phnum * phsize <= size);

      /* program segment header table */
      Elf64_Phdr *phdrt = (Elf64_Phdr *) ((char *)dfile->contents + ehdr->e_phoff);
      Elf64_Phdr *phdr;

      ELF_ASSUME_PHT(ehdr, phdrt, phdr, secstart, secend);
    }
  } else {
    ehsize = sizeof(Elf32_Ehdr);
    shsize = sizeof(Elf32_Shdr);
    phsize = sizeof(Elf32_Phdr);

    /* type cast to 32-bit layout */
    Elf32_Ehdr *ehdr32 = (Elf32_Ehdr *) dfile->contents;

    ELF_ASSUME_EHDR_IDENT(ehdr32);
    ELF_ASSUME_EHDR_TYPE_MACHINE_VERSION(ehdr32);
    /* e_entry, what to put here? */
    /* e_shoff */
    klee_assume(ehdr32->e_shoff == ehsize);
    /* e_flags, what to put here? */
    /* e_ehsize, size of elf header */
    klee_assume(ehdr32->e_ehsize == ehsize);
    ELF_ASSUME_EHDR_PHT(ehdr32, phsize, 0U, 3U);
    ELF_ASSUME_EHDR_SHT(ehdr32, shsize, 2U, 5U);
    /* e_shstrndx, we force it to be at index 1 */
    klee_assume(ehdr32->e_shstrndx == 1U);

    /* section header table */
    Elf32_Shdr *shdrt = (Elf32_Shdr *) ((char *)dfile->contents + ehdr32->e_shoff);
    Elf32_Shdr *shdr;

    /* the current available offset for real sections */
    unsigned offset = ehdr32->e_shoff + ehdr32->e_shnum * shsize;
    unsigned secstart = offset;

    ELF_ASSUME_SHT(ehdr32, shdrt, shdr, 32U, offset);

    /* now offset is the byte after all real sections */
    unsigned secend = offset;
    /* make sure we don't have more bytes than the file allows */
    klee_assume(offset <= size);

    if (ehdr32->e_phnum) {
      /* e_phoff, just let it appear after the sections */
      klee_assume(ehdr32->e_phoff == offset);
      /* make sure we don't have more bytes than the file allows */
      klee_assume(ehdr32->e_phoff + ehdr32->e_phnum * phsize <= size);

      /* program segment header table */
      Elf32_Phdr *phdrt = (Elf32_Phdr *) ((char *)dfile->contents + ehdr32->e_phoff);
      Elf32_Phdr *phdr;

      ELF_ASSUME_PHT(ehdr32, phdrt, phdr, secstart, secend);
    }
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

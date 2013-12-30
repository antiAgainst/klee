//===-- klee_init_env.c ---------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/klee.h"
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#include "fd.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdbool.h>

static void __emit_error(const char *msg) {
  klee_report_error(__FILE__, __LINE__, msg, "user.err");
}

/* Helper function that converts a string to an integer, and
   terminates the program with an error message is the string is not a
   proper number */   
static long int __str_to_int(char *s, const char *error_msg) {
  long int res = 0;
  char c;

  if (!*s) __emit_error(error_msg);

  while ((c = *s++)) {
    if (c == '\0') {
      break;
    } else if (c>='0' && c<='9') {
      res = res*10 + (c - '0');
    } else {
      __emit_error(error_msg);
    }
  }
  return res;
}

static int __isprint(const char c) {
  /* Assume ASCII */
  return (32 <= c && c <= 126);
}

static int __streq(const char *a, const char *b) {
  while (*a == *b) {
    if (!*a)
      return 1;
    a++;
    b++;
  }
  return 0;
}

static char *__get_sym_str(int numChars, char *name) {
  int i;
  char *s = malloc(numChars+1);
  klee_mark_global(s);
  klee_make_symbolic(s, numChars+1, name);

  for (i=0; i<numChars; i++)
    klee_prefer_cex(s, __isprint(s[i]));
  
  s[numChars] = '\0';
  return s;
}

static char *__get_sym_opt(const char **choices, char *name) {
  int i, j;

  // Calculate the max number of characters of all possible choices
  int numChars = 0;
  for (i=0; choices[i][0]!='\0'; i++) {
    for (j=0; choices[i][j]!='\0'; j++);
    if (j > numChars)
      numChars = j;
  }
  // malloc and symoblicize
  char *s = malloc(numChars+1);
  klee_mark_global(s);
  klee_make_symbolic(s, numChars+1, name);

  // s == opt1 | s == opt2 | ... | s == optN
  bool fullreq = false;
  for (i=0; choices[i][0]!='\0'; i++) {
    bool req = true;
    // s[0] == optX[0] & s[1] == optX[1] & ... & s[M] == optX[M]
    for (j=0; choices[i][j]!='\0'; j++)
      req &= s[j]==choices[i][j];
    // The rest should be '\0'
    for (; j < numChars; j++)
      req &= s[j]=='\0';
    fullreq |= req;
  }
  // klee_assume makes sure that the above requirements are true
  klee_assume(fullreq);

  s[numChars] = '\0';
  return s;
}

static char *__get_sym_nonopt(int numChars, const char **choices, char *name) {
  int i, j;

  char *s = malloc(numChars+1);
  klee_mark_global(s);
  klee_make_symbolic(s, numChars+1, name);

  for (i=0; choices[i][0]!='\0'; i++) {
    // If the current choice has more chars than s, then simply ignore it.
    for (j=0; choices[i][j]!='\0'; j++);
    if (j > numChars) continue;
    bool req = true;
    // s[0] == optX[0] & s[1] == optX[1] & ... & s[M] == optX[M]
    for (j=0; choices[i][j]!='\0'; j++)
      req &= s[j]==choices[i][j];
    klee_assume(req == false);
  }
  s[numChars] = '\0';

  return s;
}

static void __add_arg(int *argc, char **argv, char *arg, int argcMax) {
  if (*argc==argcMax) {
    __emit_error("too many arguments for klee_init_env");
  } else {
    argv[*argc] = arg;
    (*argc)++;
  }
}

void klee_init_env(int* argcPtr, char*** argvPtr) {
  int argc = *argcPtr;
  char** argv = *argvPtr;

  int new_argc = 0, n_args, n_nop;
  int n_opts, n_choice;
  char* new_argv[1024];
  const char *choices[512];
  unsigned max_len, min_argvs, max_argvs;
  unsigned min_opts, max_opts;
  unsigned sym_files = 0, sym_file_len = 0;
  int sym_stdout_flag = 0;
  int save_all_writes_flag = 0;
  int fd_fail = 0;
  char** final_argv;
  char sym_arg_name[5] = "arg";
  char sym_opt_name[5] = "opt";
  char sym_nop_name[5] = "str";
  unsigned sym_arg_num = 0;
  unsigned sym_opt_num = 0;
  unsigned sym_nop_num = 0;
  int k=0, i;

  sym_arg_name[4] = '\0';
  sym_opt_name[4] = '\0';
  sym_nop_name[4] = '\0';

  bool opt_list_supplied = false;

  // Recognize --help when it is the sole argument.
  if (argc == 2 && __streq(argv[1], "--help")) {
  __emit_error("klee_init_env\n\n\
usage: (klee_init_env) [options] [program arguments]\n\
  -sym-arg <N>              - Replace by a symbolic argument with length N\n\
  -sym-args <MIN> <MAX> <N> - Replace by at least MIN arguments and at most\n\
                              MAX arguments, each with maximum length N\n\
  -opt-list <N> <CHOICE>...\n\
                            - A list of N possible options <CHOICE>...,\n\
                              required by -sym-(non)opt(s)\n\
  -sym-nonopt <N>           - Replace by a symbolic argument excluding the\n\
                              choices given by -opt-list\n\
  -sym-nonopts <MIN> <MAX> <N>\n\
                            - Replace by at least MIN arguments and at most\n\
                              MAX arguments excluding the choices given by\n\
                              -opt-list, each with maximum length N\n\
  -sym-opt                  - Replace by a symbolic option selected from\n\
                              the choices given by -opt-list\n\
  -sym-opts <MIN> <MAX>     - Replace by at least MIN options and at most\n\
                              MAX options, each is selected from the choice\n\
                              given by -opt-list\n\
  -sym-files <NUM> <N>      - Make stdin and up to NUM symbolic files, each\n\
                              with maximum size N.\n\
  -sym-stdout               - Make stdout symbolic.\n\
  -max-fail <N>             - Allow up to <N> injected failures\n\
  -fd-fail                  - Shortcut for '-max-fail 1'\n\n");
  }

  while (k < argc) {
    if (__streq(argv[k], "--sym-arg") || __streq(argv[k], "-sym-arg")) {
      const char *msg = "--sym-arg expects an integer argument <max-len>";
      if (++k == argc)        
	__emit_error(msg);
		
      max_len = __str_to_int(argv[k++], msg);
      sym_arg_name[3] = '0' + sym_arg_num++;
      __add_arg(&new_argc, new_argv, 
                __get_sym_str(max_len, sym_arg_name),
                1024);
    }
    else if (__streq(argv[k], "--sym-args") || __streq(argv[k], "-sym-args")) {
      const char *msg = 
        "--sym-args expects three integer arguments <min-argvs> <max-argvs> <max-len>";

      if (k+3 >= argc)
	__emit_error(msg);
      
      k++;
      min_argvs = __str_to_int(argv[k++], msg);
      max_argvs = __str_to_int(argv[k++], msg);
      max_len = __str_to_int(argv[k++], msg);

      n_args = klee_range(min_argvs, max_argvs+1, "n_args");
      for (i=0; i < n_args; i++) {
        sym_arg_name[3] = '0' + sym_arg_num++;
        __add_arg(&new_argc, new_argv, 
                  __get_sym_str(max_len, sym_arg_name),
                  1024);
      }
    }
    else if (__streq(argv[k], "--opt-list") || __streq(argv[k], "-opt-list")) {
      const char *msg =
        "--opt-list expects at least two arguments <num-choices> <choice>...";

      if (k+2 >= argc)
    __emit_error(msg);

      k++;
      n_choice = __str_to_int(argv[k++], msg);
      opt_list_supplied = true;

      for (i=0; i < n_choice; i++)
        choices[i] = argv[k++];
      choices[n_choice] = "";
	}
    else if (__streq(argv[k], "--sym-opt") || __streq(argv[k], "-sym-opt")) {
      k++;
      if (!opt_list_supplied)
    __emit_error("--opt-list should be specified before --sym-(non)opt(s)");

      sym_opt_name[3] = '0' + sym_opt_num++;
      __add_arg(&new_argc, new_argv,
                __get_sym_opt(choices, sym_opt_name),
                1024);
    }
    else if (__streq(argv[k], "--sym-opts") || __streq(argv[k], "-sym-opts")) {
      const char *msg =
        "--sym-opts expects at least two arguments <min-opts> <max-opts>";

      if (k+2 >= argc)
    __emit_error(msg);
      if (!opt_list_supplied)
    __emit_error("--opt-list should be specified before --sym-(non)opt(s)");

      k++;
      min_opts = __str_to_int(argv[k++], msg);
      max_opts = __str_to_int(argv[k++], msg);

      n_opts = klee_range(min_opts, max_opts+1, "n_opts");
      for (i=0; i < n_opts; i++) {
        sym_opt_name[3] = '0' + sym_opt_num++;
        __add_arg(&new_argc, new_argv,
                  __get_sym_opt(choices, sym_opt_name),
                  1024);
      }
    }
    else if (__streq(argv[k], "--sym-nonopt") || __streq(argv[k], "-sym-nonopt")) {
      const char *msg = "--sym-nonopt expects at least one argument <max-len>";

      if (k+1 >= argc)
    __emit_error(msg);
      if (!opt_list_supplied)
    __emit_error("--opt-list should be specified before --sym-(non)opt(s)");

      k++;
      max_len = __str_to_int(argv[k++], msg);

      sym_nop_name[3] = '0' + sym_nop_num++;
      __add_arg(&new_argc, new_argv,
                __get_sym_nonopt(max_len, choices, sym_nop_name),
                1024);
    }
    else if (__streq(argv[k], "--sym-nonopts") || __streq(argv[k], "-sym-nonopts")) {
      const char *msg =
        "--sym-nonopts expects at least three arguments <min-strs> <max-strs> <max-len>";

      if (k+3 >= argc)
    __emit_error(msg);
      if (!opt_list_supplied)
    __emit_error("--opt-list should be specified before --sym-(non)opt(s)");

      k++;
      min_argvs = __str_to_int(argv[k++], msg);
      max_argvs = __str_to_int(argv[k++], msg);
      max_len = __str_to_int(argv[k++], msg);

      n_nop = klee_range(min_argvs, max_argvs+1, "n_nop");
      for (i=0; i < n_nop; i++) {
        sym_nop_name[3] = '0' + sym_nop_num++;
        __add_arg(&new_argc, new_argv,
                  __get_sym_nonopt(max_len, choices, sym_nop_name),
                  1024);
      }
    }
    else if (__streq(argv[k], "--sym-files") || __streq(argv[k], "-sym-files")) {
      const char* msg = "--sym-files expects two integer arguments <no-sym-files> <sym-file-len>";      

      if (k+2 >= argc)
	__emit_error(msg);
      
      k++;
      sym_files = __str_to_int(argv[k++], msg);
      sym_file_len = __str_to_int(argv[k++], msg);

    }
    else if (__streq(argv[k], "--sym-stdout") || __streq(argv[k], "-sym-stdout")) {
      sym_stdout_flag = 1;
      k++;
    }
    else if (__streq(argv[k], "--save-all-writes") || __streq(argv[k], "-save-all-writes")) {
      save_all_writes_flag = 1;
      k++;
    }
    else if (__streq(argv[k], "--fd-fail") || __streq(argv[k], "-fd-fail")) {
      fd_fail = 1;
      k++;
    }
    else if (__streq(argv[k], "--max-fail") || __streq(argv[k], "-max-fail")) {
      const char *msg = "--max-fail expects an integer argument <max-failures>";
      if (++k == argc)
	__emit_error(msg);
		
      fd_fail = __str_to_int(argv[k++], msg);
    }
    else {
      /* simply copy arguments */
      __add_arg(&new_argc, new_argv, argv[k++], 1024);
    }
  }

  final_argv = (char**) malloc((new_argc+1) * sizeof(*final_argv));
  klee_mark_global(final_argv);
  memcpy(final_argv, new_argv, new_argc * sizeof(*final_argv));
  final_argv[new_argc] = 0;

  *argcPtr = new_argc;
  *argvPtr = final_argv;

  klee_init_fds(sym_files, sym_file_len, 
		sym_stdout_flag, save_all_writes_flag, 
		fd_fail);
}


#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern int __llvm_profile_write_file(void);
extern void __llvm_profile_set_filename(const char *);

__attribute__((noinline)) static int profiledWork(int value) {
  if (value == 1) {
    return value + 10;
  }
  if (value == 2) {
    return value + 20;
  }
  return value + 30;
}

static char *resetChildFilename(void) {
  static const char suffix[] = ".profraw";
  const char *pattern = getenv("LLVM_PROFILE_FILE");
  size_t length;
  char *child;

  assert(pattern != NULL);
  length = strlen(pattern);
  child = malloc(length + 64);
  assert(child != NULL);
  if (length >= sizeof(suffix) - 1 &&
      strcmp(pattern + length - (sizeof(suffix) - 1), suffix) == 0) {
    snprintf(child, length + 64, "%.*s.child-%ld%s",
             (int)(length - (sizeof(suffix) - 1)), pattern, (long)getpid(),
             suffix);
  } else {
    snprintf(child, length + 64, "%s.child-%ld%s", pattern, (long)getpid(),
             suffix);
  }
  __llvm_profile_set_filename(child);
  return child;
}

int main(void) {
  pid_t children[3];
  int index;

  for (index = 0; index < 3; index++) {
    children[index] = fork();
    assert(children[index] >= 0);
    if (children[index] == 0) {
      char *childFilename = resetChildFilename();
      assert(profiledWork(index + 1) != 0);
      assert(__llvm_profile_write_file() == 0);
      free(childFilename);
      _Exit(0);
    }
  }
  for (index = 0; index < 3; index++) {
    int status;
    assert(waitpid(children[index], &status, 0) == children[index]);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
  assert(profiledWork(0) != 0);
  return 0;
}

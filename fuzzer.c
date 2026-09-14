#include "fuzzer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef APACHE_FUZZ_NO_APACHE
#include "apr_strings.h"
#include "covbridge.h"
#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "mpm_common.h"
#include "scoreboard.h"
#endif

#if defined(__clang__)
#pragma clang attribute push(__attribute__((no_sanitize("coverage"))), apply_to = function)
#endif

#define PACKET_DELAY_US 20000
#define ITERATION_DELAY_US 1850
#define RESPONSE_TIMEOUT_MS 500
#define RESPONSE_DRAIN_TIMEOUT_MS 10
#define MAX_RESPONSE_BYTES 65536
#define COVERAGE_TIMEOUT_MS 7000
#define APACHE_FUZZ_LAYOUT_ID UINT64_C(0x4150465a00000001)

#ifndef APACHE_FUZZ_NO_APACHE
static _Atomic int childStopping;
static _Atomic int exitGuardRegistered;
static char pathToCurrentInput[] =
    "/home/admin/software/fuzzing/apachehttp-fuzz/logs/currentInput1";
extern int __llvm_profile_write_file(void) __attribute__((weak));
extern void __llvm_profile_set_filename(const char *) __attribute__((weak));

static int currentInputPath(char *path, size_t pathSize) {
  int length = snprintf(path, pathSize, "%s-%ld", pathToCurrentInput,
                        (long)getpid());

  if (length < 0 || (size_t)length >= pathSize) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return 0;
}

static int writeCurrentInput(const uint8_t *data, size_t size) {
  char path[sizeof(pathToCurrentInput) + 32];
  size_t written = 0;
  int fd;

  if (currentInputPath(path, sizeof(path)) == -1) {
    return -1;
  }
  fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd == -1) {
    return -1;
  }
  while (written < size) {
    ssize_t result = write(fd, data + written, size - written);
    if (result > 0) {
      written += (size_t)result;
    } else if (result == -1 && errno == EINTR) {
      continue;
    } else {
      int savedError = result == 0 ? EIO : errno;
      close(fd);
      unlink(path);
      errno = savedError;
      return -1;
    }
  }
  if (close(fd) == -1) {
    int savedError = errno;
    unlink(path);
    errno = savedError;
    return -1;
  }
  return 0;
}

static int removeCurrentInput(void) {
  char path[sizeof(pathToCurrentInput) + 32];

  if (currentInputPath(path, sizeof(path)) == -1) {
    return -1;
  }
  if (unlink(path) == -1 && errno != ENOENT) {
    return -1;
  }
  return 0;
}

static void fuzzerExitAfterApacheCleanup(void) {
  if (!atomic_load_explicit(&childStopping, memory_order_acquire)) {
    return;
  }
  (void)removeCurrentInput();
  if (__llvm_profile_write_file != NULL) {
    (void)__llvm_profile_write_file();
  }
  _Exit(0);
}

static void registerFuzzerExitGuard(void) {
  int expected = 0;

  if (atomic_compare_exchange_strong_explicit(
          &exitGuardRegistered, &expected, 1, memory_order_acq_rel,
          memory_order_relaxed) &&
      atexit(fuzzerExitAfterApacheCleanup) != 0) {
    atomic_store_explicit(&exitGuardRegistered, 0, memory_order_release);
  }
}
#endif

char *ip = "::1";
int port = 5800;
char pathToTestCaseLog[] = "/home/admin/software/fuzzing/apachehttp-fuzz/logs/testCases1";

static const uint8_t keepAlivePrelude[] =
    "HEAD / HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "Connection: keep-alive\r\n"
    "\r\n";

#ifndef APACHE_FUZZ_NO_APACHE
static const uint8_t healthRequest[] =
    "HEAD / HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "Connection: close\r\n"
    "\r\n";
#endif

int decodeFuzzInput(const uint8_t *data, size_t size, struct fuzzInput *input) {
  size_t offset;

  if (data == NULL || input == NULL || size < 1) {
    return -1;
  }

  memset(input, 0, sizeof(*input));
  input->flags = data[0];

  if (!(input->flags & MULTIPACKET_FLAG)) {
    input->packetCount = 1;
    input->packets[0].data = data + 1;
    input->packets[0].size = size - 1;
    return 0;
  }

  offset = 1;
  while (offset < size) {
    size_t packetSize;

    if (size - offset < 2 || input->packetCount == MAX_PACKET_COUNT) {
      return -1;
    }

    packetSize = ((size_t)data[offset] << 8) | data[offset + 1];
    offset += 2;
    if (packetSize == 0 || packetSize > size - offset) {
      return -1;
    }

    input->packets[input->packetCount].data = data + offset;
    input->packets[input->packetCount].size = packetSize;
    input->packetCount++;
    offset += packetSize;
  }

  return input->packetCount > 0 ? 0 : -1;
}

static int connectTarget(void) {
  struct sockaddr_in6 serverAddress;
  struct timeval timeout = {.tv_sec = 0,
                            .tv_usec = RESPONSE_TIMEOUT_MS * 1000};
  int sockfd;
  int one = 1;

  sockfd = socket(AF_INET6, SOCK_STREAM, 0);
  if (sockfd == -1) {
    return -1;
  }

  memset(&serverAddress, 0, sizeof(serverAddress));
  serverAddress.sin6_family = AF_INET6;
  serverAddress.sin6_port = htons((uint16_t)port);
  if (inet_pton(AF_INET6, ip, &serverAddress.sin6_addr) != 1) {
    close(sockfd);
    return -1;
  }

  setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  if (connect(sockfd, (struct sockaddr *)&serverAddress,
              sizeof(serverAddress)) == -1) {
    close(sockfd);
    return -1;
  }
  return sockfd;
}

static int sendAll(int sockfd, const uint8_t *data, size_t size) {
  size_t sent = 0;

  while (sent < size) {
    ssize_t result = send(sockfd, data + sent, size - sent, MSG_NOSIGNAL);
    if (result > 0) {
      sent += (size_t)result;
    } else if (result == -1 && errno == EINTR) {
      continue;
    } else {
      return -1;
    }
  }
  return 0;
}

static int waitForPacketResponse(int sockfd) {
  struct pollfd socketEvent = {.fd = sockfd, .events = POLLIN};
  uint8_t response[4096];
  int pollResult;
  size_t received = 0;
  int timeout = RESPONSE_TIMEOUT_MS;

  for (;;) {
    do {
      pollResult = poll(&socketEvent, 1, timeout);
    } while (pollResult == -1 && errno == EINTR);

    if (pollResult <= 0) {
      return received > 0 ? 0 : -1;
    }
    if (socketEvent.revents & (POLLERR | POLLNVAL)) {
      return received > 0 ? 0 : -1;
    }

    for (;;) {
      size_t available = MAX_RESPONSE_BYTES - received;
      ssize_t result;

      if (available == 0) {
        return 0;
      }
      if (available > sizeof(response)) {
        available = sizeof(response);
      }
      result = recv(sockfd, response, available, MSG_DONTWAIT);
      if (result > 0) {
        received += (size_t)result;
        timeout = RESPONSE_DRAIN_TIMEOUT_MS;
        continue;
      }
      if (result == -1 && errno == EINTR) {
        continue;
      }
      if (result == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        break;
      }
      return received > 0 ? 0 : -1;
    }
  }
}

static int sendPrelude(int sockfd) {
  if (sendAll(sockfd, keepAlivePrelude, sizeof(keepAlivePrelude) - 1) == -1) {
    return -1;
  }
  return waitForPacketResponse(sockfd);
}

static int sendMultipacketData(int sockfd, const struct fuzzInput *input) {
  size_t packetNumber;

  for (packetNumber = 0; packetNumber < input->packetCount; packetNumber++) {
    const struct fuzzPacketView *packet = &input->packets[packetNumber];
    if (sendAll(sockfd, packet->data, packet->size) == -1) {
      return -1;
    }

    if (packetNumber + 1 < input->packetCount) {
      if (input->flags & WAIT_FOR_RESPONSE_FLAG) {
        if (waitForPacketResponse(sockfd) == -1) {
          return -1;
        }
      } else {
        usleep(PACKET_DELAY_US);
      }
    }
  }
  return 0;
}

#ifndef APACHE_FUZZ_NO_APACHE
static int checkServerUp(void) {
  int sockfd = connectTarget();
  int result;

  if (sockfd == -1) {
    return 0;
  }
  result = sendAll(sockfd, healthRequest, sizeof(healthRequest) - 1);
  if (result == 0) {
    result = waitForPacketResponse(sockfd);
  }
  close(sockfd);
  return result == 0;
}
#endif

int fuzzServer(const uint8_t *data, size_t size) {
  struct fuzzInput input;
  struct timeval now;
  int sockfd;
  int sendResult;
  FILE *testCases;
  size_t index;
#ifndef APACHE_FUZZ_NO_APACHE
  static cb_snapshot coverageSnapshot;
  uint64_t coverageRun;
#endif

#ifndef APACHE_FUZZ_NO_APACHE
  /* libFuzzer has registered its ExitCallback before the first input.  Add a
     later handler so Apache's normal child exit does not become a fake crash. */
  registerFuzzerExitGuard();
  cb_libfuzzer_clear();
#endif
  if (decodeFuzzInput(data, size, &input) == -1) {
    return -1;
  }

#ifndef APACHE_FUZZ_NO_APACHE
  if (writeCurrentInput(data, size) == -1) {
    fprintf(stderr, "could not preserve current input: %s\n", strerror(errno));
    _exit(2);
  }
  if (cb_begin(&coverageRun) == -1) {
    fprintf(stderr, "covbridge: could not begin input: %s\n", strerror(errno));
    _exit(2);
  }
#endif
  sockfd = connectTarget();
  if (sockfd == -1) {
#ifndef APACHE_FUZZ_NO_APACHE
    int cancelResult = cb_cancel(coverageRun);
    int cancelError = errno;
    int removeResult = removeCurrentInput();

    if (cancelResult == -1 || removeResult == -1) {
      if (removeResult != -1) {
        errno = cancelError;
      }
      fprintf(stderr, "could not cancel unsent input: %s\n", strerror(errno));
      _exit(2);
    }
#endif
    return -1;
  }

  if ((input.flags & HTTP_PRELUDE_FLAG) && sendPrelude(sockfd) == -1) {
    sendResult = -1;
    goto inputComplete;
  }

  if (input.flags & MULTIPACKET_FLAG) {
    sendResult = sendMultipacketData(sockfd, &input);
  } else {
    sendResult = sendAll(sockfd, input.packets[0].data, input.packets[0].size);
  }
  if (sendResult != -1) {
#ifndef APACHE_FUZZ_NO_LOG
    gettimeofday(&now, NULL);
    testCases = fopen(pathToTestCaseLog, "a");
    if (testCases != NULL) {
      fprintf(testCases, "%010ld:%06ld - flags=0x%02x packets=%zu - ",
              (long)now.tv_sec, (long)now.tv_usec, input.flags,
              input.packetCount);
      for (index = 1; index < size; index++) {
        fprintf(testCases, "0x%02x, ", data[index]);
      }
      fputc('\n', testCases);
      fclose(testCases);
    }
#else
    (void)now;
    (void)testCases;
    (void)index;
#endif
  }

inputComplete:
  usleep(PACKET_DELAY_US);
  close(sockfd);
#ifndef APACHE_FUZZ_NO_APACHE
  if (cb_wait_snapshot(coverageRun, &coverageSnapshot, COVERAGE_TIMEOUT_MS) ==
      -1) {
    fprintf(stderr, "covbridge: input %llu did not complete: %s\n",
            (unsigned long long)coverageRun, strerror(errno));
    _exit(2);
  }
  if (cb_libfuzzer_import(&coverageSnapshot, 0) == -1) {
    fprintf(stderr, "covbridge: could not import input %llu: %s\n",
            (unsigned long long)coverageRun, strerror(errno));
    _exit(2);
  }
  if (removeCurrentInput() == -1) {
    fprintf(stderr, "could not remove completed input: %s\n", strerror(errno));
    _exit(2);
  }
#endif
  usleep(ITERATION_DELAY_US);
  return 0;
}

#ifndef APACHE_FUZZ_NO_APACHE
extern int LLVMFuzzerRunDriver(int *argc, char ***argv,
                               int (*callback)(const uint8_t *, size_t));

char *arg_array[] = {
    "httpd",
    "/home/admin/software/fuzzing/apachehttp-fuzz/corpus",
    "-max_len=65000",
    "-detect_leaks=0",
    "-len_control=20",
    "-rss_limit_mb=20530",
    "-verbosity=4",
    NULL};

char **args_ptr = &arg_array[0];
int args_size = 7;

static char *leaderLockPath;

static int lockControllerFile(void) {
  struct flock lock = {.l_type = F_WRLCK,
                       .l_whence = SEEK_SET,
                       .l_start = 0,
                       .l_len = 0};
  int lockfd;

  lockfd = open(leaderLockPath, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
  if (lockfd == -1) {
    return -1;
  }
  while (fcntl(lockfd, F_SETLKW, &lock) == -1) {
    if (errno != EINTR) {
      close(lockfd);
      return -1;
    }
  }
  return lockfd;
}

static void *launchFuzzerThread(void *parameter) {
  int attemptNumber = 0;
  int lockfd;

  (void)parameter;
  lockfd = lockControllerFile();
  if (lockfd == -1) {
    fprintf(stderr, "ApacheFuzzer could not lock %s: %s\n", leaderLockPath,
            strerror(errno));
    return NULL;
  }
  if (cb_claim_controller(COVERAGE_TIMEOUT_MS) == -1) {
    fprintf(stderr, "covbridge: controller claim failed: %s\n",
            strerror(errno));
    close(lockfd);
    return NULL;
  }
  while (!checkServerUp()) {
    fprintf(stderr, "Waiting for Apache HTTP Server to start %d\n",
            attemptNumber++);
    sleep(1);
  }
  fprintf(stderr,
          "Apache HTTP Server is ready; fuzzing launched in controller %ld "
          "with %u shared counters\n",
          (long)getpid(), cb_slots());
  LLVMFuzzerRunDriver(&args_size, &args_ptr, fuzzServer);
  close(lockfd);
  return NULL;
}

int launchFuzzer(void) {
  pthread_t threadID;
  int result = pthread_create(&threadID, NULL, launchFuzzerThread, NULL);

  if (result != 0) {
    return -1;
  }
  pthread_detach(threadID);
  return 0;
}

typedef struct {
  int enabled;
} fuzzerServerConfig;

typedef struct {
  uint64_t run;
  int ended;
  server_rec *server;
} fuzzerConnectionState;

extern module AP_MODULE_DECLARE_DATA fuzzer_module;

static int isFuzzListener(const conn_rec *connection) {
  return connection != NULL && connection->master == NULL &&
         connection->local_addr != NULL &&
         connection->local_addr->port == (apr_port_t)port;
}

static void resetChildProfileFilename(apr_pool_t *pool) {
  static const char suffix[] = ".profraw";
  const char *pattern;
  const char *childPattern;
  size_t length;

  if (__llvm_profile_set_filename == NULL) {
    return;
  }
  pattern = getenv("LLVM_PROFILE_FILE");
  if (pattern == NULL || *pattern == '\0') {
    return;
  }
  length = strlen(pattern);
  if (length >= sizeof(suffix) - 1 &&
      strcmp(pattern + length - (sizeof(suffix) - 1), suffix) == 0) {
    const char *base =
        apr_pstrmemdup(pool, pattern, length - (sizeof(suffix) - 1));
    childPattern = apr_psprintf(pool, "%s.child-%ld%s", base,
                                (long)getpid(), suffix);
  } else {
    childPattern =
        apr_psprintf(pool, "%s.child-%ld%s", pattern, (long)getpid(), suffix);
  }
  __llvm_profile_set_filename(childPattern);
}

static void *createFuzzerServerConfig(apr_pool_t *pool, server_rec *server) {
  fuzzerServerConfig *config = apr_pcalloc(pool, sizeof(*config));
  (void)server;
  return config;
}

static const char *setApacheFuzzer(cmd_parms *command, void *unused,
                                   int enabled) {
  fuzzerServerConfig *config = ap_get_module_config(
      command->server->module_config, &fuzzer_module);
  (void)unused;
  config->enabled = enabled;
  return NULL;
}

static apr_status_t finishFuzzerConnection(void *parameter) {
  fuzzerConnectionState *state = parameter;

  if (state == NULL || state->ended || state->run == 0) {
    return APR_SUCCESS;
  }
  state->ended = 1;
  if (cb_connection_end(state->run) == -1) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, state->server,
                 "covbridge could not finish run %llu: %s",
                 (unsigned long long)state->run, strerror(errno));
  }
  return APR_SUCCESS;
}

static int fuzzerPreConnection(conn_rec *connection, void *socket) {
  fuzzerConnectionState *state;
  uint64_t run;

  (void)socket;
  if (!isFuzzListener(connection)) {
    return DECLINED;
  }
  run = cb_connection_begin();
  if (run == 0) {
    return DECLINED;
  }
  state = apr_pcalloc(connection->pool, sizeof(*state));
  state->run = run;
  state->server = connection->base_server;
  ap_set_module_config(connection->conn_config, &fuzzer_module, state);
  apr_pool_cleanup_register(connection->pool, state, finishFuzzerConnection,
                            apr_pool_cleanup_null);
  return DECLINED;
}

static int fuzzerPreCloseConnection(conn_rec *connection) {
  fuzzerConnectionState *state =
      ap_get_module_config(connection->conn_config, &fuzzer_module);
  (void)finishFuzzerConnection(state);
  return DECLINED;
}

static void fuzzerSuspendConnection(conn_rec *connection,
                                    request_rec *request) {
  (void)connection;
  (void)request;
  cb_thread_pause();
}

static void fuzzerResumeConnection(conn_rec *connection,
                                   request_rec *request) {
  fuzzerConnectionState *state =
      ap_get_module_config(connection->conn_config, &fuzzer_module);
  (void)request;
  if (state != NULL && !state->ended) {
    cb_thread_resume(state->run);
  }
}

static int fuzzerPreMpm(apr_pool_t *pool, ap_scoreboard_e scoreboardType) {
  fuzzerServerConfig *config =
      ap_get_module_config(ap_server_conf->module_config, &fuzzer_module);
  (void)pool;
  (void)scoreboardType;

  if (config == NULL || !config->enabled) {
    return OK;
  }
  if (cb_init(APACHE_FUZZ_LAYOUT_ID) == -1 && errno != EALREADY) {
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, ap_server_conf,
                 "covbridge initialization failed: %s", strerror(errno));
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
               "covbridge initialized %u shared counters before MPM fork",
               cb_slots());
  return OK;
}

static void fuzzerChildInit(apr_pool_t *pool, server_rec *server) {
  static pid_t launchedProcess = 0;
  static pid_t profileProcess = 0;
  fuzzerServerConfig *config =
      ap_get_module_config(server->module_config, &fuzzer_module);
  pid_t process = getpid();

  if (profileProcess != process) {
    resetChildProfileFilename(pool);
    profileProcess = process;
  }
  if (config == NULL || !config->enabled || launchedProcess == process) {
    return;
  }
  leaderLockPath = ap_server_root_relative(pool, "logs/fuzzer.lock");
  if (leaderLockPath == NULL) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, server,
                 "ApacheFuzzer could not resolve its controller lock path");
    return;
  }
  launchedProcess = process;
  if (launchFuzzer() == -1) {
    launchedProcess = 0;
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, server,
                 "ApacheFuzzer could not create its libFuzzer thread");
  } else {
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, server,
                 "ApacheFuzzer controller waiter enabled in worker process %ld",
                 (long)process);
  }
}

static void fuzzerChildStopping(apr_pool_t *pool, int graceful) {
  (void)pool;
  (void)graceful;
  atomic_store_explicit(&childStopping, 1, memory_order_release);
  if (removeCurrentInput() == -1) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                 "ApacheFuzzer could not remove current input: %s",
                 strerror(errno));
  }
}

static const command_rec fuzzerCommands[] = {
    AP_INIT_FLAG("ApacheFuzzer", setApacheFuzzer, NULL, RSRC_CONF,
                 "Run the in-process HTTP libFuzzer driver in this worker"),
    {.name = NULL}};

static void registerFuzzerHooks(apr_pool_t *pool) {
  (void)pool;
  ap_hook_pre_mpm(fuzzerPreMpm, NULL, NULL, APR_HOOK_LAST);
  ap_hook_child_init(fuzzerChildInit, NULL, NULL, APR_HOOK_LAST);
  ap_hook_child_stopping(fuzzerChildStopping, NULL, NULL,
                         APR_HOOK_REALLY_LAST);
  ap_hook_pre_connection(fuzzerPreConnection, NULL, NULL,
                         APR_HOOK_REALLY_FIRST);
  ap_hook_pre_close_connection(fuzzerPreCloseConnection, NULL, NULL,
                               APR_HOOK_LAST);
  ap_hook_suspend_connection(fuzzerSuspendConnection, NULL, NULL,
                             APR_HOOK_LAST);
  ap_hook_resume_connection(fuzzerResumeConnection, NULL, NULL,
                            APR_HOOK_REALLY_FIRST);
}

AP_DECLARE_MODULE(fuzzer) = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    createFuzzerServerConfig,
    NULL,
    fuzzerCommands,
    registerFuzzerHooks
#if defined(AP_MODULE_FLAG_NONE)
    , AP_MODULE_FLAG_NONE
#endif
};
#else
int launchFuzzer(void) { return -1; }
#endif

#if defined(__clang__)
#pragma clang attribute pop
#endif

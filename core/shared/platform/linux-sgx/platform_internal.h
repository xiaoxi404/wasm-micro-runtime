/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _PLATFORM_INTERNAL_H
#define _PLATFORM_INTERNAL_H

#include <inttypes.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include <sgx_thread.h>
#include <pthread.h>

#include "sgx_error.h"
#include "sgx_file.h"
#include "sgx_pthread.h"
#include "sgx_time.h"
#include "sgx_socket.h"
#include "sgx_signal.h"
#include "sgx_trts.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef BH_PLATFORM_LINUX_SGX
#define BH_PLATFORM_LINUX_SGX
#endif

#define _STACK_SIZE_ADJUSTMENT (32 * 1024)

/* Stack size of applet threads's native part.  */
#define BH_APPLET_PRESERVED_STACK_SIZE (8 * 1024 + _STACK_SIZE_ADJUSTMENT)

/* Default thread priority */
#define BH_THREAD_DEFAULT_PRIORITY 0

typedef pthread_t korp_thread;
typedef pthread_t korp_tid;
typedef pthread_mutex_t korp_mutex;
typedef pthread_cond_t korp_cond;
typedef pthread_rwlock_t korp_rwlock;
typedef unsigned int korp_sem;

#ifndef SGX_DISABLE_PTHREAD
#define OS_THREAD_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#endif

typedef int (*os_print_function_t)(const char *message);
void
os_set_print_function(os_print_function_t pf);

typedef sgx_status_t (*os_ctr_encrypt_function_t)(
    const uint8_t *p_src, const uint32_t src_len, uint8_t *p_dst,
    sgx_aes_state_handle_t sm4_ctr_handle);
void
os_set_ctr_encrypt_function(os_ctr_encrypt_function_t pf);
os_ctr_encrypt_function_t
os_get_ctr_encrypt_function(void);

typedef sgx_status_t (*os_ctr_decrypt_function_t)(
    const uint8_t *p_src, const uint32_t src_len, uint8_t *p_dst,
    sgx_aes_state_handle_t sm4_ctr_handle);
void
os_set_ctr_decrypt_function(os_ctr_decrypt_function_t pf);
os_ctr_decrypt_function_t
os_get_ctr_decrypt_function(void);

typedef sgx_status_t (*os_hash_update_function_t)(
    const uint8_t *p_src, uint32_t src_len, sgx_sha_state_handle_t sha_handle);
void
os_set_hash_handle(sgx_sha_state_handle_t enc_hash_handle,
                   sgx_sha_state_handle_t dec_hash_handle);
void
os_set_hash_update_function(os_hash_update_function_t pf);
os_hash_update_function_t
os_get_hash_update_function(void);

void
os_set_stdio_fds(uint64_t stdinfd, uint64_t stdoutfd);
uint64_t
os_get_stdin_fd(void);
uint64_t
os_get_stdout_fd(void);

char *
strcpy(char *dest, const char *src);

#define os_memory_order_acquire __ATOMIC_ACQUIRE
#define os_memory_order_release __ATOMIC_RELEASE
#define os_memory_order_seq_cst __ATOMIC_SEQ_CST
#define os_atomic_thread_fence __atomic_thread_fence

typedef int os_file_handle;
typedef DIR *os_dir_stream;
typedef int os_raw_file_handle;

static inline os_file_handle
os_get_invalid_handle(void)
{
    return -1;
}

#define os_getpagesize getpagesize

#ifdef __cplusplus
}
#endif

#endif /* end of _PLATFORM_INTERNAL_H */

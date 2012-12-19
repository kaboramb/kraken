// kraken_thread.h
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above
//   copyright notice, this list of conditions and the following disclaimer
//   in the documentation and/or other materials provided with the
//   distribution.
// * Neither the name of SecureState Consulting nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#ifndef _KRAKEN_THREAD_H
#define _KRAKEN_THREAD_H

/*
 * This is an attempt to create a way to implement threads within
 * Kraken that can eventually be ported to windows.
 */

#include <pthread.h>
#include <signal.h>
typedef pthread_t kraken_thread;
typedef pthread_mutex_t kraken_thread_mutex;

int kraken_thread_create(kraken_thread *k_thread, void *routine, void *args);
int kraken_thread_join(kraken_thread *k_thread);
int kraken_thread_is_alive(kraken_thread *k_thread);

int kraken_thread_mutex_init(kraken_thread_mutex *k_mutex);
int kraken_thread_mutex_destroy(kraken_thread_mutex *k_mutex);
int kraken_thread_mutex_lock(kraken_thread_mutex *k_mutex);
int kraken_thread_mutex_trylock(kraken_thread_mutex *k_mutex);
int kraken_thread_mutex_unlock(kraken_thread_mutex *k_mutex);

#endif

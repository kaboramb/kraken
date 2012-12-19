// kraken_thread.c
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

#include <stdlib.h>

#include "kraken_thread.h"
#include "logging.h"

int kraken_thread_create(kraken_thread *k_thread, void *routine, void *args) {
	int response;
	response = pthread_create(k_thread, NULL, routine, args);
	return response;
}

int kraken_thread_join(kraken_thread *k_thread) {
	pthread_join(*k_thread, NULL);
	logging_log("kraken.thread", LOGGING_TRACE, "thread successfully joined");
	return 0;
}

int kraken_thread_is_alive(kraken_thread *k_thread) {
	/*
	 * returns 1 on is up, otherwise 0
	 */
	int response;
	response = pthread_kill(*k_thread, 0);
	if (response == 0) {
		return 1;
	}
	return 0;
}

int kraken_thread_mutex_init(kraken_thread_mutex *k_mutex) {
	if (pthread_mutex_init(k_mutex, NULL) != 0) {
		return -1;
	}
	return 0;
}

int kraken_thread_mutex_destroy(kraken_thread_mutex *k_mutex) {
	if (pthread_mutex_destroy(k_mutex) != 0) {
		return -1;
	}
	return 0;
}

int kraken_thread_mutex_lock(kraken_thread_mutex *k_mutex) {
	if (pthread_mutex_lock(k_mutex) != 0) {
		return -1;
	}
	return 0;
}

int kraken_thread_mutex_trylock(kraken_thread_mutex *k_mutex) {
	if (pthread_mutex_trylock(k_mutex) != 0) {
		return -1;
	}
	return 0;
}

int kraken_thread_mutex_unlock(kraken_thread_mutex *k_mutex) {
	if (pthread_mutex_unlock(k_mutex) != 0) {
		return -1;
	}
	return 0;
}

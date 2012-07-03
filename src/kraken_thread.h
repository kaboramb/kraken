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
int kraken_thread_mutex_unlock(kraken_thread_mutex *k_mutex);

#endif

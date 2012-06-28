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
	pthread_mutex_init(k_mutex, NULL);
	return 0;
}

int kraken_thread_mutex_destroy(kraken_thread_mutex *k_mutex) {
	pthread_mutex_destroy(k_mutex);
	return 0;
}

int kraken_thread_mutex_lock(kraken_thread_mutex *k_mutex) {
	pthread_mutex_lock(k_mutex);
	return 0;
}

int kraken_thread_mutex_unlock(kraken_thread_mutex *k_mutex) {
	pthread_mutex_unlock(k_mutex);
	return 0;
}

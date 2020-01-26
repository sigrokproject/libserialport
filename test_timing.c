#include "config.h"
#include "libserialport.h"
#include "libserialport_internal.h"
#include <assert.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	(void) argc;
	(void) argv;
	struct time a, b, c;
	struct timeval tv;
	struct timeout to;

	printf("Testing arithmetic\n");
	time_set_ms(&a, 10050);
	time_set_ms(&b, 100);
	assert(time_greater(&a, &b));
	assert(!time_greater(&b, &a));
	time_add(&a, &b, &c);
	assert(time_as_ms(&c) == 10150);
	time_sub(&a, &b, &c);
	assert(time_as_ms(&c) == 9950);
	time_as_timeval(&a, &tv);
	assert(tv.tv_sec == 10);
	assert(tv.tv_usec == 50000);
	time_get(&a);
	printf("Sleeping for 1s\n");
	sleep(1);
	time_get(&b);
	time_sub(&b, &a, &c);
	printf("Measured: %ums\n", time_as_ms(&c));
	assert(time_as_ms(&c) >= 950);
	assert(time_as_ms(&c) <= 1050);
	printf("Starting 3s timeout\n");
	timeout_start(&to, 3000);
	printf("Time to wait: %dms\n", timeout_remaining_ms(&to));
	printf("Sleeping for 1s\n");
	sleep(1);
	timeout_update(&to);
	assert(!timeout_check(&to));
	printf("Sleeping for 1s\n");
	sleep(1);
	timeout_update(&to);
	assert(!timeout_check(&to));
	printf("Remaining: %ums\n", timeout_remaining_ms(&to));
	printf("Sleeping for 1s\n");
	sleep(1);
	timeout_update(&to);
	assert(timeout_check(&to));
	printf("Timeout expired\n");
	printf("Starting 2s timeout\n");
	timeout_start(&to, 2000);
	printf("Limiting steps to 1s\n");
	timeout_limit(&to, 1000);
	printf("Time to wait: %ums\n", timeout_remaining_ms(&to));
	printf("Sleeping for 1s\n");
	sleep(1);
	timeout_update(&to);
	assert(!timeout_check(&to));
	printf("Remaining: %ums\n", timeout_remaining_ms(&to));
	printf("Sleeping for 1s\n");
	sleep(1);
	timeout_update(&to);
	assert(timeout_check(&to));
	printf("Timeout expired\n");

	return 0;
}

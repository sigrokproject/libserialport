/*
 * This file is part of the libserialport project.
 *
 * Copyright (C) 2019 Martin Ling <martin-libserialport@earth.li>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "libserialport_internal.h"

SP_PRIV void time_get(struct time *time)
{
#ifdef _WIN32
	LARGE_INTEGER count;
	QueryPerformanceCounter(&count);
	time->ticks = count.QuadPart;
#elif defined(HAVE_CLOCK_GETTIME)
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
		clock_gettime(CLOCK_REALTIME, &ts);
	time->tv.tv_sec = ts.tv_sec;
	time->tv.tv_usec = ts.tv_nsec / 1000;
#elif defined(__APPLE__)
	mach_timebase_info_data_t info;
	mach_timebase_info(&info);
	uint64_t ticks = mach_absolute_time();
	uint64_t ns = (ticks * info.numer) / info.denom;
	time->tv.tv_sec = ns / 1000000000;
	time->tv.tv_usec = (ns % 1000000000) / 1000;
#else
	gettimeofday(&time->tv, NULL);
#endif
}

SP_PRIV void time_set_ms(struct time *time, unsigned int ms)
{
#ifdef _WIN32
	LARGE_INTEGER frequency;
	QueryPerformanceFrequency(&frequency);
	time->ticks = ms * (frequency.QuadPart / 1000);
#else
	time->tv.tv_sec = ms / 1000;
	time->tv.tv_usec = (ms % 1000) * 1000;
#endif
}

SP_PRIV void time_add(const struct time *a,
		const struct time *b, struct time *result)
{
#ifdef _WIN32
	result->ticks = a->ticks + b->ticks;
#else
	timeradd(&a->tv, &b->tv, &result->tv);
#endif
}

SP_PRIV void time_sub(const struct time *a,
		const struct time *b, struct time *result)
{
#ifdef _WIN32
	result->ticks = a->ticks - b->ticks;
#else
	timersub(&a->tv, &b->tv, &result->tv);
#endif
}

SP_PRIV bool time_greater(const struct time *a, const struct time *b)
{
#ifdef _WIN32
	return (a->ticks > b->ticks);
#else
	return timercmp(&a->tv, &b->tv, >);
#endif
}

SP_PRIV void time_as_timeval(const struct time *time, struct timeval *tv)
{
#ifdef _WIN32
	LARGE_INTEGER frequency;
	QueryPerformanceFrequency(&frequency);
	tv->tv_sec = (long) (time->ticks / frequency.QuadPart);
	tv->tv_usec = (long) ((time->ticks % frequency.QuadPart) /
		(frequency.QuadPart / 1000000));
#else
	*tv = time->tv;
#endif
}

SP_PRIV unsigned int time_as_ms(const struct time *time)
{
#ifdef _WIN32
	LARGE_INTEGER frequency;
	QueryPerformanceFrequency(&frequency);
	return (unsigned int) (time->ticks / (frequency.QuadPart / 1000));
#else
	return time->tv.tv_sec * 1000 + time->tv.tv_usec / 1000;
#endif
}

SP_PRIV void timeout_start(struct timeout *timeout, unsigned int timeout_ms)
{
	timeout->ms = timeout_ms;

	/* Get time at start of operation. */
	time_get(&timeout->start);
	/* Define duration of timeout. */
	time_set_ms(&timeout->delta, timeout_ms);
	/* Calculate time at which we should give up. */
	time_add(&timeout->start, &timeout->delta, &timeout->end);
	/* Disable limit unless timeout_limit() called. */
	timeout->limit_ms = 0;
	/* First blocking call has not yet been made. */
	timeout->calls_started = false;
}

SP_PRIV void timeout_limit(struct timeout *timeout, unsigned int limit_ms)
{
	timeout->limit_ms = limit_ms;
	timeout->overflow = (timeout->ms > timeout->limit_ms);
	time_set_ms(&timeout->delta_max, timeout->limit_ms);
}

SP_PRIV bool timeout_check(struct timeout *timeout)
{
	if (!timeout->calls_started)
		return false;

	if (timeout->ms == 0)
		return false;

	time_get(&timeout->now);
	time_sub(&timeout->end, &timeout->now, &timeout->delta);
	if (timeout->limit_ms)
		if ((timeout->overflow = time_greater(&timeout->delta, &timeout->delta_max)))
			timeout->delta = timeout->delta_max;

	return time_greater(&timeout->now, &timeout->end);
}

SP_PRIV void timeout_update(struct timeout *timeout)
{
	timeout->calls_started = true;
}

#ifndef _WIN32
SP_PRIV struct timeval *timeout_timeval(struct timeout *timeout)
{
	if (timeout->ms == 0)
		return NULL;

	time_as_timeval(&timeout->delta, &timeout->delta_tv);

	return &timeout->delta_tv;
}
#endif

SP_PRIV unsigned int timeout_remaining_ms(struct timeout *timeout)
{
	if (timeout->limit_ms && timeout->overflow)
		return timeout->limit_ms;
	else
		return time_as_ms(&timeout->delta);
}

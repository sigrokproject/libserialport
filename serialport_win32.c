/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * This file is part of the libserialport project.
 *
 * Copyright (C) 2010-2012 Bert Vermeulen <bert@biot.com>
 * Copyright (C) 2010-2015 Uwe Hermann <uwe@hermann-uwe.de>
 * Copyright (C) 2013-2015 Martin Ling <martin-libserialport@earth.li>
 * Copyright (C) 2013 Matthias Heidbrink <m-sigrok@heidbrink.biz>
 * Copyright (C) 2014 Aurelien Jacobs <aurel@gnuage.org>
 * Copyright (C) 2026 H. Peter Anvin <hpa@zytor.com>
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

SP_PRIV void sp_platform_init_port(struct sp_port *port)
{
	port->usb_path = NULL;
	port->hdl = INVALID_HANDLE_VALUE;
	port->write_buf = NULL;
	port->write_buf_size = 0;
}

SP_PRIV enum sp_return sp_platform_canonicalize_port_name(const char *portname,
	char **canonical_name)
{
	(void)portname;
	(void)canonical_name;
	return SP_OK;
}

SP_PRIV bool sp_platform_port_is_open(const struct sp_port *port)
{
	return port->hdl != INVALID_HANDLE_VALUE;
}

SP_PRIV void sp_platform_free_port(struct sp_port *port)
{
	if (port->usb_path)
		free(port->usb_path);
	if (port->write_buf)
		free(port->write_buf);
}

static enum sp_return restart_wait(struct sp_port *port)
{
	DWORD wait_result;

	if (port->wait_running) {
		/* Check status of running wait operation. */
		if (GetOverlappedResult(port->hdl, &port->wait_ovl,
				&wait_result, FALSE)) {
			DEBUG("Previous wait completed");
			port->last_wait_thread_exited = FALSE;
			port->wait_running = FALSE;
		} else if (GetLastError() == ERROR_OPERATION_ABORTED) {
			/* This error is returned if the last thread that called
			 * restart_wait() has exited while WaitCommEvent() was
			 * still active. In that case we don't consider that to
			 * be an error. Just restart the wait procedure instead.
			 */
			DEBUG("Previous wait ended due to previous thread exiting");
			/* We need to record that the wait thread exited before
			 * we called WaitCommEvent(). This is because the exit of
			 * the previous thread always generates a spurious wakeup,
			 * and if no data has been received in the mean time, the
			 * WaitCommEvent() wouldn't be restarted a second time by
			 * restart_wait_if_needed() after a read call after the
			 * spurious wakeup.
			 */
			port->last_wait_thread_exited = TRUE;
			port->wait_running = FALSE;
		} else if (GetLastError() == ERROR_IO_INCOMPLETE) {
			DEBUG("Previous wait still running");
			port->last_wait_thread_exited = FALSE;
			RETURN_OK();
		} else {
			RETURN_FAIL("GetOverlappedResult() failed");
		}
	}

	if (!port->wait_running) {
		/* Start new wait operation. */
		if (WaitCommEvent(port->hdl, &port->events,
				&port->wait_ovl)) {
			DEBUG("New wait returned, events already pending");
		} else if (GetLastError() == ERROR_IO_PENDING) {
			DEBUG("New wait running in background");
			port->wait_running = TRUE;
		} else {
			RETURN_FAIL("WaitCommEvent() failed");
		}
	}

	RETURN_OK();
}

static enum sp_return await_write_completion(struct sp_port *port)
{
	TRACE("%p", port);
	DWORD bytes_written;
	BOOL result;

	/* Wait for previous non-blocking write to complete, if any. */
	if (port->writing) {
		DEBUG("Waiting for previous write to complete");
		result = GetOverlappedResult(port->hdl, &port->write_ovl, &bytes_written, TRUE);
		port->writing = 0;
		if (!result)
			RETURN_FAIL("Previous write failed to complete");
		DEBUG("Previous write completed");
	}

	RETURN_OK();
}

static enum sp_return restart_wait_if_needed(struct sp_port *port, unsigned int bytes_read)
{
	DWORD errors;
	COMSTAT comstat;

	/* Only skip restarting the wait operation if we didn't have a
	 * wakeup immediately following the exit of the last thread that
	 * re-initiated the wait loop.
	 */
	if (!port->last_wait_thread_exited && bytes_read == 0)
		RETURN_OK();

	if (ClearCommError(port->hdl, &errors, &comstat) == 0)
		RETURN_FAIL("ClearCommError() failed");

	if (comstat.cbInQue == 0)
		TRY(restart_wait(port));

	RETURN_OK();
}

SP_PRIV enum sp_return sp_platform_open(struct sp_port *port, enum sp_mode flags)
{
	enum sp_return ret;

	DWORD desired_access = 0, flags_and_attributes = 0;
	char *escaped_port_name;

	/* Prefix port name with '\\.\' to work with ports above COM9. */
	if (!(escaped_port_name = malloc(strlen(port->name) + 5)))
		RETURN_ERROR(SP_ERR_MEM, "Escaped port name malloc failed");
	sprintf(escaped_port_name, "\\\\.\\%s", port->name);

	/* Map 'flags' to the OS-specific settings. */
	flags_and_attributes = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED;
	if (flags & SP_MODE_READ)
		desired_access |= GENERIC_READ;
	if (flags & SP_MODE_WRITE)
		desired_access |= GENERIC_WRITE;

	port->hdl = CreateFileA(escaped_port_name, desired_access, 0, 0,
			 OPEN_EXISTING, flags_and_attributes, 0);

	free(escaped_port_name);

	if (port->hdl == INVALID_HANDLE_VALUE)
		RETURN_FAIL("Port CreateFile() failed");

	/* All timeouts initially disabled. */
	port->timeouts.ReadIntervalTimeout = 0;
	port->timeouts.ReadTotalTimeoutMultiplier = 0;
	port->timeouts.ReadTotalTimeoutConstant = 0;
	port->timeouts.WriteTotalTimeoutMultiplier = 0;
	port->timeouts.WriteTotalTimeoutConstant = 0;

	if (SetCommTimeouts(port->hdl, &port->timeouts) == 0) {
		sp_close(port);
		RETURN_FAIL("SetCommTimeouts() failed");
	}

	/* Prepare OVERLAPPED structures. */
#define INIT_OVERLAPPED(ovl) do { \
	memset(&port->ovl, 0, sizeof(port->ovl)); \
	port->ovl.hEvent = INVALID_HANDLE_VALUE; \
	if ((port->ovl.hEvent = CreateEvent(NULL, TRUE, TRUE, NULL)) \
			== INVALID_HANDLE_VALUE) { \
		sp_close(port); \
		RETURN_FAIL(#ovl "CreateEvent() failed"); \
	} \
} while (0)

	INIT_OVERLAPPED(read_ovl);
	INIT_OVERLAPPED(write_ovl);
	INIT_OVERLAPPED(wait_ovl);

	/* Set event mask for RX and error events. */
	if (SetCommMask(port->hdl, EV_RXCHAR | EV_ERR) == 0) {
		sp_close(port);
		RETURN_FAIL("SetCommMask() failed");
	}

	port->writing = FALSE;
	port->wait_running = FALSE;

	ret = restart_wait(port);

	if (ret < 0) {
		sp_close(port);
		RETURN_CODEVAL(ret);
	}

	RETURN_OK();
}

SP_PRIV enum sp_return sp_platform_set_default_config(struct sp_port *port,
	struct port_data *data)
{
	DWORD errors;
	COMSTAT status;

	/* Set sane port settings. */
	data->dcb.fBinary = TRUE;
	data->dcb.fDsrSensitivity = FALSE;
	data->dcb.fErrorChar = FALSE;
	data->dcb.fNull = FALSE;
	data->dcb.fAbortOnError = FALSE;

	if (ClearCommError(port->hdl, &errors, &status) == 0)
		RETURN_FAIL("ClearCommError() failed");
	RETURN_OK();
}

static enum sp_return add_handle(struct sp_event_set *event_set,
		event_handle handle, enum sp_event mask)
{
	void *new_handles;
	enum sp_event *new_masks;

	TRACE("%p, %d, %d", event_set, handle, mask);

	if (!(new_handles = realloc(event_set->handles,
			sizeof(event_handle) * (event_set->count + 1))))
		RETURN_ERROR(SP_ERR_MEM, "Handle array realloc() failed");

	event_set->handles = new_handles;

	if (!(new_masks = realloc(event_set->masks,
			sizeof(enum sp_event) * (event_set->count + 1))))
		RETURN_ERROR(SP_ERR_MEM, "Mask array realloc() failed");

	event_set->masks = new_masks;

	((event_handle *) event_set->handles)[event_set->count] = handle;
	event_set->masks[event_set->count] = mask;

	event_set->count++;

	RETURN_OK();
}

static enum sp_return get_config(struct sp_port *port, struct port_data *data,
	struct sp_port_config *config)
{
	TRACE("%p, %p, %p", port, data, config);

	DEBUG_FMT("Getting configuration for port %s", port->name);
	if (!GetCommState(port->hdl, &data->dcb))
		RETURN_FAIL("GetCommState() failed");

	config->baudrate = data->dcb.BaudRate;
	config->bits     = data->dcb.ByteSize;

	switch (data->dcb.Parity) {
	case NOPARITY:
		config->parity = SP_PARITY_NONE;
		break;
	case ODDPARITY:
		config->parity = SP_PARITY_ODD;
		break;
	case EVENPARITY:
		config->parity = SP_PARITY_EVEN;
		break;
	case MARKPARITY:
		config->parity = SP_PARITY_MARK;
		break;
	case SPACEPARITY:
		config->parity = SP_PARITY_SPACE;
		break;
	default:
		config->parity = -1;
	}

	switch (data->dcb.StopBits) {
	case ONESTOPBIT:
		config->stopbits = 1;
		break;
	case TWOSTOPBITS:
		config->stopbits = 2;
		break;
	default:
		config->stopbits = -1;
	}

	switch (data->dcb.fRtsControl) {
	case RTS_CONTROL_DISABLE:
		config->rts = SP_RTS_OFF;
		break;
	case RTS_CONTROL_ENABLE:
		config->rts = SP_RTS_ON;
		break;
	case RTS_CONTROL_HANDSHAKE:
		config->rts = SP_RTS_FLOW_CONTROL;
		break;
	default:
		config->rts = -1;
	}

	config->cts = data->dcb.fOutxCtsFlow ? SP_CTS_FLOW_CONTROL : SP_CTS_IGNORE;

	switch (data->dcb.fDtrControl) {
	case DTR_CONTROL_DISABLE:
		config->dtr = SP_DTR_OFF;
		break;
	case DTR_CONTROL_ENABLE:
		config->dtr = SP_DTR_ON;
		break;
	case DTR_CONTROL_HANDSHAKE:
		config->dtr = SP_DTR_FLOW_CONTROL;
		break;
	default:
		config->dtr = -1;
	}

	config->dsr = data->dcb.fOutxDsrFlow ? SP_DSR_FLOW_CONTROL : SP_DSR_IGNORE;

	if (data->dcb.fInX) {
		if (data->dcb.fOutX)
			config->xon_xoff = SP_XONXOFF_INOUT;
		else
			config->xon_xoff = SP_XONXOFF_IN;
	} else {
		if (data->dcb.fOutX)
			config->xon_xoff = SP_XONXOFF_OUT;
		else
			config->xon_xoff = SP_XONXOFF_DISABLED;
	}

	RETURN_OK();
}

static enum sp_return set_config(struct sp_port *port, struct port_data *data,
	const struct sp_port_config *config)
{
	TRACE("%p, %p, %p", port, data, config);

	DEBUG_FMT("Setting configuration for port %s", port->name);
	BYTE* new_buf;

	TRY(await_write_completion(port));

	if (config->baudrate >= 0) {
		data->dcb.BaudRate = config->baudrate;

		/* Allocate write buffer for 50ms of data at baud rate. */
		port->write_buf_size = max(config->baudrate / (8 * 20), 1);
		new_buf = realloc(port->write_buf, port->write_buf_size);
		if (!new_buf)
			RETURN_ERROR(SP_ERR_MEM, "Allocating write buffer failed");
		port->write_buf = new_buf;
	}

	if (config->bits >= 0) {
		switch (config->bits) {
		case 5:
		case 6:
		case 7:
		case 8:
			data->dcb.ByteSize = (BYTE)config->bits;
			break;
		default:
			RETURN_ERROR(SP_ERR_ARG, "Invalid data bits setting");
		}
	}

	if (config->parity >= 0) {
		switch (config->parity) {
		case SP_PARITY_NONE:
			data->dcb.Parity = NOPARITY;
			break;
		case SP_PARITY_ODD:
			data->dcb.Parity = ODDPARITY;
			break;
		case SP_PARITY_EVEN:
			data->dcb.Parity = EVENPARITY;
			break;
		case SP_PARITY_MARK:
			data->dcb.Parity = MARKPARITY;
			break;
		case SP_PARITY_SPACE:
			data->dcb.Parity = SPACEPARITY;
			break;
		default:
			RETURN_ERROR(SP_ERR_ARG, "Invalid parity setting");
		}
	}

	if (config->stopbits >= 0) {
		switch (config->stopbits) {
		/* Note: There's also ONE5STOPBITS == 1.5 (unneeded so far). */
		case 1:
			data->dcb.StopBits = ONESTOPBIT;
			break;
		case 2:
			data->dcb.StopBits = TWOSTOPBITS;
			break;
		default:
			RETURN_ERROR(SP_ERR_ARG, "Invalid stop bit setting");
		}
	}

	if (config->rts >= 0) {
		switch (config->rts) {
		case SP_RTS_OFF:
			data->dcb.fRtsControl = RTS_CONTROL_DISABLE;
			break;
		case SP_RTS_ON:
			data->dcb.fRtsControl = RTS_CONTROL_ENABLE;
			break;
		case SP_RTS_FLOW_CONTROL:
			data->dcb.fRtsControl = RTS_CONTROL_HANDSHAKE;
			break;
		default:
			RETURN_ERROR(SP_ERR_ARG, "Invalid RTS setting");
		}
	}

	if (config->cts >= 0) {
		switch (config->cts) {
		case SP_CTS_IGNORE:
			data->dcb.fOutxCtsFlow = FALSE;
			break;
		case SP_CTS_FLOW_CONTROL:
			data->dcb.fOutxCtsFlow = TRUE;
			break;
		default:
			RETURN_ERROR(SP_ERR_ARG, "Invalid CTS setting");
		}
	}

	if (config->dtr >= 0) {
		switch (config->dtr) {
		case SP_DTR_OFF:
			data->dcb.fDtrControl = DTR_CONTROL_DISABLE;
			break;
		case SP_DTR_ON:
			data->dcb.fDtrControl = DTR_CONTROL_ENABLE;
			break;
		case SP_DTR_FLOW_CONTROL:
			data->dcb.fDtrControl = DTR_CONTROL_HANDSHAKE;
			break;
		default:
			RETURN_ERROR(SP_ERR_ARG, "Invalid DTR setting");
		}
	}

	if (config->dsr >= 0) {
		switch (config->dsr) {
		case SP_DSR_IGNORE:
			data->dcb.fOutxDsrFlow = FALSE;
			break;
		case SP_DSR_FLOW_CONTROL:
			data->dcb.fOutxDsrFlow = TRUE;
			break;
		default:
			RETURN_ERROR(SP_ERR_ARG, "Invalid DSR setting");
		}
	}

	if (config->xon_xoff >= 0) {
		switch (config->xon_xoff) {
		case SP_XONXOFF_DISABLED:
			data->dcb.fInX = FALSE;
			data->dcb.fOutX = FALSE;
			break;
		case SP_XONXOFF_IN:
			data->dcb.fInX = TRUE;
			data->dcb.fOutX = FALSE;
			break;
		case SP_XONXOFF_OUT:
			data->dcb.fInX = FALSE;
			data->dcb.fOutX = TRUE;
			break;
		case SP_XONXOFF_INOUT:
			data->dcb.fInX = TRUE;
			data->dcb.fOutX = TRUE;
			break;
		default:
			RETURN_ERROR(SP_ERR_ARG, "Invalid XON/XOFF setting");
		}
	}

	if (!SetCommState(port->hdl, &data->dcb))
		RETURN_FAIL("SetCommState() failed");

	RETURN_OK();
}

SP_PRIV enum sp_return sp_platform_get_config(struct sp_port *port,
	struct port_data *data, struct sp_port_config *config)
{
	return get_config(port, data, config);
}

SP_PRIV enum sp_return sp_platform_set_config(struct sp_port *port,
	struct port_data *data, const struct sp_port_config *config)
{
	return set_config(port, data, config);
}

SP_API enum sp_return sp_get_port_handle(const struct sp_port *port,
                                         void *result_ptr)
{
	TRACE("%p, %p", port, result_ptr);

	if (!port)
		RETURN_ERROR(SP_ERR_ARG, "Null port");
	if (!result_ptr)
		RETURN_ERROR(SP_ERR_ARG, "Null result pointer");

	HANDLE *handle_ptr = result_ptr;
	*handle_ptr = port->hdl;

	RETURN_OK();
}

SP_API enum sp_return sp_close(struct sp_port *port)
{
	TRACE("%p", port);

	CHECK_OPEN_PORT();

	DEBUG_FMT("Closing port %s", port->name);

	/* Returns non-zero upon success, 0 upon failure. */
	if (CloseHandle(port->hdl) == 0)
		RETURN_FAIL("Port CloseHandle() failed");
	port->hdl = INVALID_HANDLE_VALUE;

	/* Close event handles for overlapped structures. */
#define CLOSE_OVERLAPPED(ovl) do { \
	if (port->ovl.hEvent != INVALID_HANDLE_VALUE && \
		CloseHandle(port->ovl.hEvent) == 0) \
		RETURN_FAIL(# ovl "event CloseHandle() failed"); \
} while (0)
	CLOSE_OVERLAPPED(read_ovl);
	CLOSE_OVERLAPPED(write_ovl);
	CLOSE_OVERLAPPED(wait_ovl);

	if (port->write_buf) {
		free(port->write_buf);
		port->write_buf = NULL;
	}

	RETURN_OK();
}

SP_API enum sp_return sp_flush(struct sp_port *port, enum sp_buffer buffers)
{
	TRACE("%p, 0x%x", port, buffers);

	CHECK_OPEN_PORT();

	if (buffers > SP_BUF_BOTH)
		RETURN_ERROR(SP_ERR_ARG, "Invalid buffer selection");

	const char *buffer_names[] = {"no", "input", "output", "both"};

	DEBUG_FMT("Flushing %s buffers on port %s",
		buffer_names[buffers], port->name);

	DWORD flags = 0;
	if (buffers & SP_BUF_INPUT)
		flags |= PURGE_RXCLEAR;
	if (buffers & SP_BUF_OUTPUT)
		flags |= PURGE_TXCLEAR;

	/* Returns non-zero upon success, 0 upon failure. */
	if (PurgeComm(port->hdl, flags) == 0)
		RETURN_FAIL("PurgeComm() failed");

	if (buffers & SP_BUF_INPUT)
		TRY(restart_wait(port));
	RETURN_OK();
}

SP_API enum sp_return sp_drain(struct sp_port *port)
{
	TRACE("%p", port);

	CHECK_OPEN_PORT();

	DEBUG_FMT("Draining port %s", port->name);

	/* Returns non-zero upon success, 0 upon failure. */
	if (FlushFileBuffers(port->hdl) == 0)
		RETURN_FAIL("FlushFileBuffers() failed");
	RETURN_OK();
}

SP_API enum sp_return sp_blocking_write(struct sp_port *port, const void *buf,
                                        size_t count, unsigned int timeout_ms)
{
	TRACE("%p, %p, %d, %d", port, buf, count, timeout_ms);

	CHECK_OPEN_PORT();

	if (!buf)
		RETURN_ERROR(SP_ERR_ARG, "Null buffer");

	if (timeout_ms)
		DEBUG_FMT("Writing %d bytes to port %s, timeout %d ms",
			count, port->name, timeout_ms);
	else
		DEBUG_FMT("Writing %d bytes to port %s, no timeout",
			count, port->name);

	if (count == 0)
		RETURN_INT(0);

	DWORD remaining_ms, write_size, bytes_written;
	size_t remaining_bytes, total_bytes_written = 0;
	const uint8_t *write_ptr = (uint8_t *) buf;
	bool result;
	struct timeout timeout;

	timeout_start(&timeout, timeout_ms);

	TRY(await_write_completion(port));

	while (total_bytes_written < count) {

		if (timeout_check(&timeout))
			break;

		remaining_ms = timeout_remaining_ms(&timeout);

		if (port->timeouts.WriteTotalTimeoutConstant != remaining_ms) {
			port->timeouts.WriteTotalTimeoutConstant = remaining_ms;
			if (SetCommTimeouts(port->hdl, &port->timeouts) == 0)
				RETURN_FAIL("SetCommTimeouts() failed");
		}

		/* Reduce write size if it exceeds the WriteFile limit. */
		remaining_bytes = count - total_bytes_written;
		if (remaining_bytes > WRITEFILE_MAX_SIZE)
			write_size = WRITEFILE_MAX_SIZE;
		else
			write_size = (DWORD) remaining_bytes;

		/* Start write. */

		result = WriteFile(port->hdl, write_ptr, write_size, NULL, &port->write_ovl);

		timeout_update(&timeout);

		if (result) {
			DEBUG("Write completed immediately");
			bytes_written = write_size;
		} else if (GetLastError() == ERROR_IO_PENDING) {
			DEBUG("Waiting for write to complete");
			if (GetOverlappedResult(port->hdl, &port->write_ovl, &bytes_written, TRUE) == 0) {
				if (GetLastError() == ERROR_SEM_TIMEOUT) {
					DEBUG("Write timed out");
					break;
				} else {
					RETURN_FAIL("GetOverlappedResult() failed");
				}
			}
			DEBUG_FMT("Write completed, %d/%d bytes written", bytes_written, write_size);
		} else {
			RETURN_FAIL("WriteFile() failed");
		}

		write_ptr += bytes_written;
		total_bytes_written += bytes_written;
	}

	RETURN_INT((int) total_bytes_written);
}

SP_API enum sp_return sp_nonblocking_write(struct sp_port *port,
                                           const void *buf, size_t count)
{
	TRACE("%p, %p, %d", port, buf, count);

	CHECK_OPEN_PORT();

	if (!buf)
		RETURN_ERROR(SP_ERR_ARG, "Null buffer");

	DEBUG_FMT("Writing up to %d bytes to port %s", count, port->name);

	if (count == 0)
		RETURN_INT(0);

	size_t buf_bytes;

	/* Check whether previous write is complete. */
	if (port->writing) {
		if (HasOverlappedIoCompleted(&port->write_ovl)) {
			DEBUG("Previous write completed");
			port->writing = 0;
		} else {
			DEBUG("Previous write not complete");
			/* Can't take a new write until the previous one finishes. */
			RETURN_INT(0);
		}
	}

	/* Set timeout. */
	if (port->timeouts.WriteTotalTimeoutConstant != 0) {
		port->timeouts.WriteTotalTimeoutConstant = 0;
		if (SetCommTimeouts(port->hdl, &port->timeouts) == 0)
			RETURN_FAIL("SetCommTimeouts() failed");
	}

	/* Reduce count if it exceeds the WriteFile limit. */
	if (count > WRITEFILE_MAX_SIZE)
		count = WRITEFILE_MAX_SIZE;

	/* Copy data to our write buffer. */
	buf_bytes = min(port->write_buf_size, count);
	memcpy(port->write_buf, buf, buf_bytes);

	/* Start asynchronous write. */
	if (WriteFile(port->hdl, port->write_buf, (DWORD) buf_bytes, NULL, &port->write_ovl) == 0) {
		if (GetLastError() == ERROR_IO_PENDING) {
			if ((port->writing = !HasOverlappedIoCompleted(&port->write_ovl)))
				DEBUG("Asynchronous write completed immediately");
			else
				DEBUG("Asynchronous write running");
		} else {
			/* Actual failure of some kind. */
			RETURN_FAIL("WriteFile() failed");
		}
	}

	DEBUG("All bytes written immediately");

	RETURN_INT((int) buf_bytes);
}

SP_API enum sp_return sp_blocking_read(struct sp_port *port, void *buf,
                                       size_t count, unsigned int timeout_ms)
{
	TRACE("%p, %p, %d, %d", port, buf, count, timeout_ms);

	CHECK_OPEN_PORT();

	if (!buf)
		RETURN_ERROR(SP_ERR_ARG, "Null buffer");

	if (timeout_ms)
		DEBUG_FMT("Reading %d bytes from port %s, timeout %d ms",
			count, port->name, timeout_ms);
	else
		DEBUG_FMT("Reading %d bytes from port %s, no timeout",
			count, port->name);

	if (count == 0)
		RETURN_INT(0);

	DWORD bytes_read;

	/* Set timeout. */
	if (port->timeouts.ReadIntervalTimeout != 0 ||
			port->timeouts.ReadTotalTimeoutMultiplier != 0 ||
			port->timeouts.ReadTotalTimeoutConstant != timeout_ms) {
		port->timeouts.ReadIntervalTimeout = 0;
		port->timeouts.ReadTotalTimeoutMultiplier = 0;
		port->timeouts.ReadTotalTimeoutConstant = timeout_ms;
		if (SetCommTimeouts(port->hdl, &port->timeouts) == 0)
			RETURN_FAIL("SetCommTimeouts() failed");
	}

	/* Start read. */
	if (ReadFile(port->hdl, buf, (DWORD) count, NULL, &port->read_ovl)) {
		DEBUG("Read completed immediately");
		bytes_read = (DWORD) count;
	} else if (GetLastError() == ERROR_IO_PENDING) {
		DEBUG("Waiting for read to complete");
		if (GetOverlappedResult(port->hdl, &port->read_ovl, &bytes_read, TRUE) == 0)
			RETURN_FAIL("GetOverlappedResult() failed");
		DEBUG_FMT("Read completed, %d/%d bytes read", bytes_read, count);
	} else {
		RETURN_FAIL("ReadFile() failed");
	}

	TRY(restart_wait_if_needed(port, bytes_read));

	RETURN_INT((int) bytes_read);

}

SP_API enum sp_return sp_blocking_read_next(struct sp_port *port, void *buf,
                                            size_t count, unsigned int timeout_ms)
{
	TRACE("%p, %p, %d, %d", port, buf, count, timeout_ms);

	CHECK_OPEN_PORT();

	if (!buf)
		RETURN_ERROR(SP_ERR_ARG, "Null buffer");

	if (count == 0)
		RETURN_ERROR(SP_ERR_ARG, "Zero count");

	if (timeout_ms)
		DEBUG_FMT("Reading next max %d bytes from port %s, timeout %d ms",
			count, port->name, timeout_ms);
	else
		DEBUG_FMT("Reading next max %d bytes from port %s, no timeout",
			count, port->name);

	DWORD bytes_read = 0;

	/* If timeout_ms == 0, set maximum timeout. */
	DWORD timeout_val = (timeout_ms == 0 ? MAXDWORD - 1 : timeout_ms);

	/* Set timeout. */
	if (port->timeouts.ReadIntervalTimeout != MAXDWORD ||
			port->timeouts.ReadTotalTimeoutMultiplier != MAXDWORD ||
			port->timeouts.ReadTotalTimeoutConstant != timeout_val) {
		port->timeouts.ReadIntervalTimeout = MAXDWORD;
		port->timeouts.ReadTotalTimeoutMultiplier = MAXDWORD;
		port->timeouts.ReadTotalTimeoutConstant = timeout_val;
		if (SetCommTimeouts(port->hdl, &port->timeouts) == 0)
			RETURN_FAIL("SetCommTimeouts() failed");
	}

	/* Loop until we have at least one byte, or timeout is reached. */
	while (bytes_read == 0) {
		/* Start read. */
		if (ReadFile(port->hdl, buf, (DWORD) count, &bytes_read, &port->read_ovl)) {
			DEBUG("Read completed immediately");
		} else if (GetLastError() == ERROR_IO_PENDING) {
			DEBUG("Waiting for read to complete");
			if (GetOverlappedResult(port->hdl, &port->read_ovl, &bytes_read, TRUE) == 0)
				RETURN_FAIL("GetOverlappedResult() failed");
			if (bytes_read > 0) {
				DEBUG("Read completed");
			} else if (timeout_ms > 0) {
				DEBUG("Read timed out");
				break;
			} else {
				DEBUG("Restarting read");
			}
		} else {
			RETURN_FAIL("ReadFile() failed");
		}
	}

	TRY(restart_wait_if_needed(port, bytes_read));

	RETURN_INT(bytes_read);

}

SP_API enum sp_return sp_nonblocking_read(struct sp_port *port, void *buf,
                                          size_t count)
{
	TRACE("%p, %p, %d", port, buf, count);

	CHECK_OPEN_PORT();

	if (!buf)
		RETURN_ERROR(SP_ERR_ARG, "Null buffer");

	DEBUG_FMT("Reading up to %d bytes from port %s", count, port->name);

	DWORD bytes_read;

	/* Set timeout. */
	if (port->timeouts.ReadIntervalTimeout != MAXDWORD ||
			port->timeouts.ReadTotalTimeoutMultiplier != 0 ||
			port->timeouts.ReadTotalTimeoutConstant != 0) {
		port->timeouts.ReadIntervalTimeout = MAXDWORD;
		port->timeouts.ReadTotalTimeoutMultiplier = 0;
		port->timeouts.ReadTotalTimeoutConstant = 0;
		if (SetCommTimeouts(port->hdl, &port->timeouts) == 0)
			RETURN_FAIL("SetCommTimeouts() failed");
	}

	/* Do read. */
	if (ReadFile(port->hdl, buf, (DWORD) count, NULL, &port->read_ovl) == 0)
		if (GetLastError() != ERROR_IO_PENDING)
			RETURN_FAIL("ReadFile() failed");

	/* Get number of bytes read. */
	if (GetOverlappedResult(port->hdl, &port->read_ovl, &bytes_read, FALSE) == 0)
		RETURN_FAIL("GetOverlappedResult() failed");

	TRY(restart_wait_if_needed(port, bytes_read));

	RETURN_INT(bytes_read);
}

SP_API enum sp_return sp_input_waiting(struct sp_port *port)
{
	TRACE("%p", port);

	CHECK_OPEN_PORT();

	DEBUG_FMT("Checking input bytes waiting on port %s", port->name);

	DWORD errors;
	COMSTAT comstat;

	if (ClearCommError(port->hdl, &errors, &comstat) == 0)
		RETURN_FAIL("ClearCommError() failed");
	RETURN_INT(comstat.cbInQue);
}

SP_API enum sp_return sp_output_waiting(struct sp_port *port)
{
	TRACE("%p", port);

	CHECK_OPEN_PORT();

	DEBUG_FMT("Checking output bytes waiting on port %s", port->name);

	DWORD errors;
	COMSTAT comstat;

	if (ClearCommError(port->hdl, &errors, &comstat) == 0)
		RETURN_FAIL("ClearCommError() failed");
	RETURN_INT(comstat.cbOutQue);
}

SP_API enum sp_return sp_add_port_events(struct sp_event_set *event_set,
	const struct sp_port *port, enum sp_event mask)
{
	TRACE("%p, %p, %d", event_set, port, mask);

	if (!event_set)
		RETURN_ERROR(SP_ERR_ARG, "Null event set");

	if (!port)
		RETURN_ERROR(SP_ERR_ARG, "Null port");

	if (mask > (SP_EVENT_RX_READY | SP_EVENT_TX_READY | SP_EVENT_ERROR))
		RETURN_ERROR(SP_ERR_ARG, "Invalid event mask");

	if (!mask)
		RETURN_OK();

	enum sp_event handle_mask;
	if ((handle_mask = mask & SP_EVENT_TX_READY))
		TRY(add_handle(event_set, port->write_ovl.hEvent, handle_mask));
	if ((handle_mask = mask & (SP_EVENT_RX_READY | SP_EVENT_ERROR)))
		TRY(add_handle(event_set, port->wait_ovl.hEvent, handle_mask));

	RETURN_OK();
}

SP_API enum sp_return sp_wait(struct sp_event_set *event_set,
                              unsigned int timeout_ms)
{
	TRACE("%p, %d", event_set, timeout_ms);

	if (!event_set)
		RETURN_ERROR(SP_ERR_ARG, "Null event set");

	if (WaitForMultipleObjects(event_set->count, event_set->handles, FALSE,
			timeout_ms ? timeout_ms : INFINITE) == WAIT_FAILED)
		RETURN_FAIL("WaitForMultipleObjects() failed");

	RETURN_OK();
}

SP_API enum sp_return sp_get_signals(struct sp_port *port,
                                     enum sp_signal *signals)
{
	TRACE("%p, %p", port, signals);

	CHECK_OPEN_PORT();

	if (!signals)
		RETURN_ERROR(SP_ERR_ARG, "Null result pointer");

	DEBUG_FMT("Getting control signals for port %s", port->name);

	*signals = 0;
	DWORD bits;
	if (GetCommModemStatus(port->hdl, &bits) == 0)
		RETURN_FAIL("GetCommModemStatus() failed");
	if (bits & MS_CTS_ON)
		*signals |= SP_SIG_CTS;
	if (bits & MS_DSR_ON)
		*signals |= SP_SIG_DSR;
	if (bits & MS_RLSD_ON)
		*signals |= SP_SIG_DCD;
	if (bits & MS_RING_ON)
		*signals |= SP_SIG_RI;
	RETURN_OK();
}

SP_API enum sp_return sp_start_break(struct sp_port *port)
{
	TRACE("%p", port);

	CHECK_OPEN_PORT();
	if (SetCommBreak(port->hdl) == 0)
		RETURN_FAIL("SetCommBreak() failed");

	RETURN_OK();
}

SP_API enum sp_return sp_end_break(struct sp_port *port)
{
	TRACE("%p", port);

	CHECK_OPEN_PORT();
	if (ClearCommBreak(port->hdl) == 0)
		RETURN_FAIL("ClearCommBreak() failed");

	RETURN_OK();
}

SP_API int sp_last_error_code(void)
{
	TRACE_VOID();
	RETURN_INT(GetLastError());
}

SP_API char *sp_last_error_message(void)
{
	TRACE_VOID();

	char *message;
	DWORD error = GetLastError();

	DWORD length = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR) &message,
		0, NULL );

	if (length >= 2 && message[length - 2] == '\r')
		message[length - 2] = '\0';

	RETURN_STRING(message);
}

SP_API void sp_free_error_message(char *message)
{
	TRACE("%s", message);

	LocalFree(message);

	RETURN();
}

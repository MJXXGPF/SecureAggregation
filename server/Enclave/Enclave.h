#pragma once
#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include "Enclave_t.h"
#include <assert.h>

#if defined(__cplusplus)
extern "C" {
#endif

	void printf(const char *fmt, ...)
	{
		char buf[BUFSIZ] = { '\0' };
		va_list ap;
		va_start(ap, fmt);
		vsnprintf(buf, BUFSIZ, fmt, ap);
		va_end(ap);
		ocall_print_string(buf);

	}


#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */

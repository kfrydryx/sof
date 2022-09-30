/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2019 Intel Corporation. All rights reserved.
 *
 * Author: Slawomir Blauciak <slawomir.blauciak@linux.intel.com>
 */

#ifdef __SOF_DRIVERS_ALH__

#ifndef __PLATFORM_DRIVERS_ALH__
#define __PLATFORM_DRIVERS_ALH__

#include <stdint.h>
/* No ALH on LUNARLAKE */
#endif /* __PLATFORM_DRIVERS_ALH__ */

#else

#error "This file shouldn't be included from outside of sof/drivers/alh.h"

#endif

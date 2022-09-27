// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright(c) 2022 Intel Corporation. All rights reserved.
//
// Author: Krzysztof Frydryk <krzysztofx.frydryk@intel.com>

/**
 * \file
 * \brief Xtensa asynchronous messages implementation file
 * \authors Krzysztof Frydryk <krzysztofx.frydryk@intel.com>
 */

#include <sof/lib/cpu.h>
#include <sof/lib/ams.h>
#include <xtos-structs.h>

struct async_message_service **arch_ams_get(void)
{
	struct core_context *ctx = (struct core_context *)cpu_read_threadptr();

	return &ctx->ams;
}

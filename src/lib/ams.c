// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2022 Intel Corporation
//
// Author: Krzysztof Frydryk <krzysztofx.frydryk@intel.com>

#include <sof/lib/memory.h>
#include <sof/lib/cpu.h>
#include <sof/coherent.h>
#include <sof/drivers/interrupt.h>
#include <sof/schedule/edf_schedule.h>
#include <sof/schedule/schedule.h>
#include <sof/schedule/task.h>
#include <sof/ipc/topology.h>
#include <sof/drivers/idc.h>
#include <sof/lib/alloc.h>
#include <sof/lib/memory.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sof/lib/ams.h>

LOG_MODULE_REGISTER(ams, CONFIG_SOF_LOG_LEVEL);

DECLARE_SOF_UUID("ams", ams_uuid, 0xea9c4bca, 0x5b7d, 0x48c6,
		 0x95, 0x86, 0x55, 0x3e, 0x27, 0x23, 0x5b, 0xeb);

DECLARE_TR_CTX(ams_tr, SOF_UUID(ams_uuid), LOG_LEVEL_INFO);

static struct ams_context ctx;
static struct ams_shared_context shared_ctx;

static struct ams_shared_context __sparse_cache *ams_acquire(struct ams_shared_context __sparse_cache *shared)
{
	struct coherent __sparse_cache *c = coherent_acquire_thread(&shared->c,
								    sizeof(*shared));

	return attr_container_of(c, struct ams_shared_context __sparse_cache,
					c, __sparse_cache);
}

static void ams_release(struct ams_shared_context __sparse_cache *shared)
{
	coherent_release_thread(&shared->c, sizeof(*shared));
}

static int ams_message_send_over_ixc(struct async_message_service *ams, uint32_t slot,
				     struct ams_routing_entry *target,
				     void *ctx)
{
#if CONFIG_SMP
	send_message_over_ixc(ams, slot, target);
	return 0;
#else
	return -EINVAL;
#endif
}

static struct uuid_idx __sparse_cache *ams_find_uuid_entry_by_uuid(struct ams_shared_context __sparse_cache *ctx_shared,
								   uint8_t const uuid[AMS_MESSAGE_UUID_SIZE])
{
	uint32_t index;
	struct uuid_idx __sparse_cache *uuid_table = ctx_shared->uuid_table;
	size_t uuid_table_size = ctx_shared->uuid_table_size;

	if (uuid == NULL)
		return NULL;

	/* try to find existing entry */
	for (index = 0; index < uuid_table_size; index++) {
		if (memcmp(uuid_table[index].message_uuid,
			   uuid, AMS_MESSAGE_UUID_SIZE) == 0) {
			return &uuid_table[index];
		}
	}

	/* and add new one if needed */
	for (index = 0; index < uuid_table_size; index++) {
		if (uuid_table[index].message_type_id == AMS_INVALID_MSG_TYPE) {
			int ec = memcpy_s(uuid_table[index].message_uuid,
					  sizeof(uuid_table[index].message_uuid),
					  uuid, AMS_MESSAGE_UUID_SIZE);
			if (ec != 0)
				return NULL;

			uuid_table[index].message_type_id = ++ctx_shared->last_used_msg_id;
			return &uuid_table[index];
		}
	}

	return NULL;
}

int ams_get_message_type_id(const uint8_t message_uuid[AMS_MESSAGE_UUID_SIZE],
			    uint32_t *message_type_id)
{
	struct async_message_service *ams = sof_get()->ams;
	struct uuid_idx __sparse_cache *uuid_entry;
	struct ams_shared_context __sparse_cache *shared_c;

	if (ams->ams_context == NULL)
		return -EINVAL;

	*message_type_id = AMS_INVALID_MSG_TYPE;

	shared_c = ams_acquire(ams->ams_context->shared);

	uuid_entry = ams_find_uuid_entry_by_uuid(shared_c, message_uuid);
	if (uuid_entry == NULL) {
		ams_release(shared_c);
		return -EINVAL;
	}

	*message_type_id = uuid_entry->message_type_id;
	ams_release(shared_c);

	return 0;
}

int32_t ams_find_uuid_index_by_msg_type_id(struct ams_shared_context __sparse_cache *ctx_shared,
					   uint32_t const message_type_id)
{
	int32_t idx = 0;

	if (message_type_id == AMS_INVALID_MSG_TYPE)
		return -EINVAL;

	for (const struct uuid_idx __sparse_cache *iter = ctx_shared->uuid_table;
	     iter->message_type_id != AMS_INVALID_MSG_TYPE;
	     iter++) {
		if (message_type_id == iter->message_type_id)
			return idx;

		idx++;
	}

	return -ENOENT;
}

int ams_register_producer(uint32_t message_type_id,
			  uint16_t module_id,
			  uint16_t instance_id)
{
	struct async_message_service *ams = sof_get()->ams;
	struct ams_producer __sparse_cache *producer_table;
	struct ams_shared_context __sparse_cache *shared_c;
	int32_t idx;

	if (ams->ams_context == NULL)
		return -EINVAL;

	shared_c = ams_acquire(ams->ams_context->shared);

	idx = ams_find_uuid_index_by_msg_type_id(shared_c, message_type_id);
	if (idx < 0) {
		ams_release(shared_c);
		return -EINVAL;
	}

	producer_table = shared_c->producer_table;
	for (uint32_t iter = 0; iter < shared_c->producer_table_size; iter++) {
		/* Search for first invalid entry */
		if (producer_table[iter].message_type_id == AMS_INVALID_MSG_TYPE) {
			producer_table[iter].message_type_id = message_type_id;
			producer_table[iter].producer_module_id = module_id;
			producer_table[iter].producer_instance_id = instance_id;
			break;
		}
	}

	ams_release(shared_c);
	return 0;
}

int ams_unregister_producer(uint32_t message_type_id,
			    uint16_t module_id,
			    uint16_t instance_id)
{
	struct async_message_service *ams = sof_get()->ams;
	struct ams_producer __sparse_cache *producer_routing_table;
	struct ams_shared_context __sparse_cache *shared_c;
	int32_t idx;

	if (ams->ams_context == NULL)
		return -EINVAL;

	shared_c = ams_acquire(ams->ams_context->shared);

	idx = ams_find_uuid_index_by_msg_type_id(shared_c, message_type_id);
	if (idx < 0) {
		ams_release(shared_c);
		return -EINVAL;
	}

	producer_routing_table = shared_c->producer_table;
	for (uint32_t iter = 0; iter < shared_c->producer_table_size; iter++) {
		/* Search for first invalid entry */
		if ((producer_routing_table[iter].message_type_id == message_type_id) &&
		    (producer_routing_table[iter].producer_instance_id == instance_id) &&
		    (producer_routing_table[iter].producer_module_id == module_id)) {
			producer_routing_table[iter].message_type_id = AMS_INVALID_MSG_TYPE;
			break;
		}
	}
	ams_release(shared_c);
	return 0;
}

int ams_register_consumer(uint32_t message_type_id,
			  uint16_t module_id,
			  uint16_t instance_id,
			  ams_msg_callback_fn function,
			  void *ctx)
{
	struct async_message_service *ams = sof_get()->ams;
	struct ams_routing_entry __sparse_cache *routing_table;
	struct ams_shared_context __sparse_cache *shared_c;
	int err = -EINVAL;

	if (ams->ams_context == NULL || function == NULL)
		return -EINVAL;

	shared_c = ams_acquire(ams->ams_context->shared);

	routing_table = shared_c->rt_table;
	for (uint32_t iter = 0; iter < shared_c->routing_table_size; iter++) {
		/* Search for first invalid entry */
		if (routing_table[iter].message_type_id == AMS_INVALID_MSG_TYPE) {
			/* Add entry to routing table for local service */
			routing_table[iter].consumer_callback = function;
			routing_table[iter].message_type_id = message_type_id;
			routing_table[iter].consumer_instance_id = instance_id;
			routing_table[iter].consumer_module_id = module_id;
			routing_table[iter].consumer_core_id = cpu_get_id();
			routing_table[iter].ctx = ctx;

			/* Exit loop since we added new entry */
			err = 0;
			break;
		}
	}

	ams_release(shared_c);
	return err;
}

int ams_unregister_consumer(uint32_t message_type_id,
			    uint16_t module_id,
			    uint16_t instance_id,
			    ams_msg_callback_fn function)
{
	struct async_message_service *ams = sof_get()->ams;
	struct ams_routing_entry __sparse_cache *routing_table;
	struct ams_shared_context __sparse_cache *shared_c;
	int err = -EINVAL;

	if (ams->ams_context == NULL)
		return -EINVAL;

	shared_c = ams_acquire(ams->ams_context->shared);
	routing_table = shared_c->rt_table;
	for (uint32_t iter = 0; iter < shared_c->routing_table_size; iter++) {
		/* Search for required entry */
		if ((routing_table[iter].message_type_id == message_type_id) &&
		    (routing_table[iter].consumer_module_id == module_id) &&
		    (routing_table[iter].consumer_instance_id == instance_id) &&
		    (routing_table[iter].consumer_callback == function)) {
			/* Remove this entry from routing table */
			routing_table[iter].message_type_id = AMS_INVALID_MSG_TYPE;
			routing_table[iter].consumer_callback = NULL;

			/* Exit loop since we removed entry */
			err = 0;
			break;
		}
	}

	ams_release(shared_c);
	return err;
}

static uint32_t ams_push_slot(struct ams_shared_context __sparse_cache *ctx_shared,
			      const struct ams_message_payload *msg,
			      uint16_t module_id, uint16_t instance_id)
{
	int err;

	for (uint32_t i = 0; i < ARRAY_SIZE(ctx_shared->slots); ++i) {
		if (ctx_shared->slot_uses[i] == 0) {
			err = memcpy_s(ctx_shared->slots[i].u.msg_raw,
				       sizeof(ctx_shared->slots[i].u.msg_raw),
				       msg, AMS_MESSAGE_SIZE(msg));

			if (err != 0)
				return AMS_INVALID_SLOT;

			ctx_shared->slots[i].module_id = module_id;
			ctx_shared->slots[i].instance_id = instance_id;
			ctx_shared->slot_done[i] = 0;

			return i;
		}
	}

	return AMS_INVALID_SLOT;
}

static uint32_t ams_get_ixc_route_to_target(uint32_t source_core, uint32_t target_core)
{
	if (source_core >= CONFIG_CORE_COUNT || target_core >= CONFIG_CORE_COUNT)
		return -EINVAL;
	/* core 0 can target any core */
	if (source_core == 0)
		return target_core;
	/* other cores must proxy thorugh main core */
	return source_core == target_core ? target_core : 0;
}

static int ams_message_send_internal(struct async_message_service *ams,
				     const struct ams_message_payload *const ams_message_payload,
				     uint16_t module_id, uint16_t instance_id,
				     uint32_t incoming_slot)
{
	bool found_any = false;
	bool incoming = (incoming_slot != AMS_INVALID_SLOT);
	struct ams_routing_entry __sparse_cache *routing_table;
	struct ams_shared_context __sparse_cache *shared_c;
	uint32_t forwarded;
	uint32_t slot;
	struct ams_routing_entry ams_target;
	uint32_t ixc_route;
	int err = 0;

	if (ams->ams_context == NULL || ams_message_payload == NULL)
		return -EINVAL;

	shared_c = ams_acquire(ams->ams_context->shared);

	if (incoming)
		shared_c->slot_done[incoming_slot] |= BIT(cpu_get_id());

	routing_table = shared_c->rt_table;

	/* first search for external consumer and try to reserve slot right away */
	slot = AMS_INVALID_SLOT;
	for (uint32_t iter = 0; iter < shared_c->routing_table_size; iter++) {
		if (routing_table[iter].message_type_id != ams_message_payload->message_type_id)
			continue;

		/* check if we want to limit to specific module */
		if (module_id != AMS_ANY && instance_id != AMS_ANY) {
			if (routing_table[iter].consumer_module_id != module_id ||
			    routing_table[iter].consumer_instance_id != instance_id) {
				continue;
			}
		}
		ams_target = routing_table[iter];
		ixc_route = ams_get_ixc_route_to_target(cpu_get_id(),
							ams_target.consumer_core_id);
		if (ixc_route != cpu_get_id()) {
			if (incoming) {
				slot = incoming_slot;
			} else {
				slot = ams_push_slot(shared_c,
						     ams_message_payload, module_id,
						     instance_id);
				if (slot == AMS_INVALID_SLOT) {
					ams_release(shared_c);
					return -EINVAL;
				}
			}
		}
	}

	for (uint32_t iter = 0; iter < shared_c->routing_table_size; iter++) {
		/* Search for required entry */
		if (routing_table[iter].message_type_id != ams_message_payload->message_type_id)
			continue;

		/* check if we want to limit to specific module* */
		if (module_id != AMS_ANY && instance_id != AMS_ANY) {
			if (routing_table[iter].consumer_module_id != module_id ||
			    routing_table[iter].consumer_instance_id != instance_id) {
				continue;
			}
		}

		found_any = true;
		ams_target = routing_table[iter];
		ixc_route = ams_get_ixc_route_to_target(cpu_get_id(),
							ams_target.consumer_core_id);

		if (ixc_route == cpu_get_id()) {
			/* we are on target core already */
			/* release lock here, callback are NOT supposed to change routing_table */
			ams_release(shared_c);

			ams_target.consumer_callback(ams_message_payload, ams_target.ctx);
			err = 0;
		} else {
			/* we have to go through idc */
			if (incoming) {
				/* if bit is set we are forwarding it again */
				if (shared_c->slot_done[incoming_slot] & BIT(ams_target.consumer_core_id)) {
					/* slot was already processed for that core, skip it */
					continue;
				}
			}
			/* if bit clear */
			if ((forwarded & BIT(ams_target.consumer_core_id)) == 0) {
				/* we have consumer for previously untouched core */

				/* bump uses count, mark current as processed already */
				if (slot != AMS_INVALID_SLOT) {
					shared_c->slot_uses[slot]++;
					shared_c->slot_done[slot] |= BIT(cpu_get_id());
				}

				/* release lock here, so other core can acquire it again */
				ams_release(shared_c);

				if (slot != AMS_INVALID_SLOT) {
					forwarded |= BIT(cpu_get_id());
					err = ams_message_send_over_ixc(ams, slot,
									&ams_target,
									ctx.callback_context);
					if (err != 0) {
						/* idc not sent, update slot refs locally */
						shared_c = ams_acquire(ams->ams_context->shared);
						shared_c->slot_uses[slot]--;
						shared_c->slot_done[slot] |= ams_target.consumer_core_id;
						ams_release(shared_c);
					}
				}
			} else {
				/* should not happen but skip reacquiring just in case */
				continue;
			}
		}

		/* acquire shared context lock again */
		shared_c = ams_acquire(ams->ams_context->shared);
	}

	if (incoming)
		shared_c->slot_uses[incoming_slot]--;

	ams_release(shared_c);

	if (!found_any)
		tr_err(&ams_tr, "No entries found!");

	return err;
}

int ams_send(const struct ams_message_payload *const ams_message_payload)
{
	struct async_message_service *ams = sof_get()->ams;

	return ams_message_send_internal(ams, ams_message_payload, AMS_ANY, AMS_ANY,
					 AMS_INVALID_SLOT);
}

int ams_message_send_mi(struct async_message_service *ams,
			const struct ams_message_payload *const ams_message_payload,
			uint16_t target_module, uint16_t target_instance)
{
	return ams_message_send_internal(ams, ams_message_payload, target_module,
					 target_instance, AMS_INVALID_SLOT);
}

int ams_send_mi(const struct ams_message_payload *const ams_message_payload,
		uint16_t module_id, uint16_t instance_id)
{
	struct async_message_service *ams = sof_get()->ams;

	return ams_message_send_mi(ams, ams_message_payload, module_id, instance_id);
}

int send_message_over_ixc(struct async_message_service *ams, uint32_t slot,
			  struct ams_routing_entry *target)
{
	int ret;

	if (target == NULL)
		return -EINVAL;

	uint32_t ixc_route = ams_get_ixc_route_to_target(cpu_get_id(),
							 target->consumer_core_id);

	struct idc_msg ams_request = {
		.header = IDC_MSG_AMS | slot,
		.extension = IDC_MSG_AMS_EXT,
		.core = ixc_route,
		.size = 0,
		.payload = NULL};

	/* send IDC message */
	ret = idc_send_msg(&ams_request, IDC_BLOCKING);

	return ret;
}

int get_input_async_pin_props(struct async_message_service *ams, uint16_t module_id,
			      uint16_t instance_id,
			      uint32_t max_size,
			      uint32_t *input_count,
			      struct async_pin_props *pin_props)
{
	struct ams_routing_entry __sparse_cache *routing_table;
	struct ams_shared_context __sparse_cache *shared_c;
	uint32_t count = 0;
	int32_t index;
	int err = 0;

	if (pin_props == NULL)
		return -EINVAL;

	shared_c = ams_acquire(ams->ams_context->shared);
	routing_table = shared_c->rt_table;

	for (uint32_t i = 0; i < shared_c->routing_table_size; i++) {
		if ((routing_table[i].consumer_instance_id == instance_id) &&
		    (routing_table[i].consumer_module_id == module_id)) {
			if (count == max_size) {
				err = -EINVAL;
				break;
			}

			index = ams_find_uuid_index_by_msg_type_id(shared_c,
								   routing_table[i].message_type_id);
			if (index >= 0) {
				memcpy_s(&pin_props[count].message_type_uuid, AMS_MESSAGE_UUID_SIZE,
					 &shared_c->uuid_table[index].message_uuid,
					 AMS_MESSAGE_UUID_SIZE);
				count++;
			} else {
				tr_err(&ams_tr, "get_input_async_pin_props(): uuid index not found for message_type_id: %u",
				       routing_table[i].message_type_id);
			}
		}
	}

	ams_release(shared_c);
	if (err == 0)
		*input_count = count;

	return err;
}

int get_output_async_pin_props(struct async_message_service *ams, uint16_t module_id,
			       uint16_t instance_id,
			       uint32_t max_size,
			       uint32_t *output_count,
			       struct async_pin_props *pin_props)
{
	struct ams_producer __sparse_cache *producer_table;
	struct ams_shared_context __sparse_cache *shared_c;
	uint32_t count = 0;
	int32_t index;
	int err = 0;

	if (pin_props == NULL)
		return -EINVAL;

	shared_c = ams_acquire(ams->ams_context->shared);
	producer_table = shared_c->producer_table;

	for (uint32_t i = 0; i < shared_c->producer_table_size; i++) {
		if ((producer_table[i].producer_instance_id == instance_id) &&
		    (producer_table[i].producer_module_id == module_id)) {
			if (count == max_size) {
				err = -EINVAL;
				break;
			}

			index = ams_find_uuid_index_by_msg_type_id(shared_c,
								   producer_table[i].message_type_id);
			if (index >= 0) {
				memcpy_s(&pin_props[count].message_type_uuid, AMS_MESSAGE_UUID_SIZE,
					 &shared_c->uuid_table[index].message_uuid,
					 AMS_MESSAGE_UUID_SIZE);
				count++;
			} else {
				tr_err(&ams_tr, "get_output_async_pin_props(): uuid index not found for message_type_id: %u",
				       producer_table[i].message_type_id);
			}
		}
	}

	ams_release(shared_c);
	if (err == 0)
		*output_count = count;

	return err;
}

static int ams_process_slot(struct async_message_service *ams, uint32_t slot)
{
	struct ams_shared_context __sparse_cache *shared_c;
	struct ams_message_payload msg;
	uint16_t module_id;
	uint16_t instance_id;

	shared_c = ams_acquire(ams->ams_context->shared);

	msg = shared_c->slots[slot].u.msg;
	module_id = shared_c->slots[slot].module_id;
	instance_id = shared_c->slots[slot].instance_id;

	ams_release(shared_c);
	tr_info(&ams_tr, "ams_process_slot slot %d msg %d from 0x%08x",
		slot, msg.message_type_id,
		msg.producer_module_id << 16 | msg.producer_instance_id);

	return ams_message_send_internal(ams, &msg, module_id, instance_id, slot);
}

#if CONFIG_SMP

static void ams_task_add_slot_to_process(struct ams_task *ams_task, uint32_t slot)
{
	int flags;

	flags = arch_interrupt_global_disable();
	ams_task->pending_slots |= BIT(slot);
	arch_interrupt_global_enable(flags);
}

int process_incoming_message(uint32_t slot)
{
	struct async_message_service *ams = sof_get()->ams;
	struct ams_task *task = &ams->ams_task;

	ams_task_add_slot_to_process(task, slot);

	return schedule_task(&task->ams_task, 0, 100);
}

static int process_slot(struct async_message_service *ams, uint32_t slot)
{
	return ams_process_slot(ams, slot);
}
#endif /* CONFIG_SMP */

/* ams task */

static enum task_state process_message(void *arg)
{
	struct ams_task *ams_task = arg;
	uint32_t slot;
	int flags;

	ams_task->is_in_do_work = true;
	slot = 31 - XT_NSAU(ams_task->pending_slots);

	process_slot(ams_task->ams, slot);

	flags = arch_interrupt_global_disable();
	ams_task->pending_slots &= ~BIT(slot);
	arch_interrupt_global_enable(flags);
	ams_task->is_in_do_work = false;
	schedule_task_cancel(&ams_task->ams_task);

	return SOF_TASK_STATE_COMPLETED;
}

struct task_ops ams_task_ops = {
	.run = process_message,
	.complete = NULL,
	.get_deadline = NULL,
};

static int ams_task_init(void)
{
	struct async_message_service *ams = sof_get()->ams;
	struct ams_task *task = &ams->ams_task;

	task->ams = ams;
	if (schedule_task_init_edf(&task->ams_task, SOF_UUID(ams_uuid),
				   &ams_task_ops, task, 0, 0)) {
		tr_err(&ams_tr, "Could not init AMS task!");
		return -EINVAL;
	}

	return 0;
}

static SHARED_DATA struct async_message_service ams_struct;

static int ams_create_shared_context(struct ams_shared_context *ctx)
{
	ctx->last_used_msg_id = AMS_INVALID_MSG_TYPE;
	ctx->routing_table_size = AMS_ROUTING_TABLE_SIZE;
	ctx->producer_table_size = AMS_ROUTING_TABLE_SIZE;
	ctx->uuid_table_size = AMS_SERVICE_UUID_TABLE_SIZE;
	coherent_init_thread(ctx, c);
	coherent_shared_thread(ctx, c);

	return 0;
}

int ams_init(void)
{
	sof_get()->ams = &ams_struct;

	struct async_message_service *ams = sof_get()->ams;

#if CONFIG_SMP
	ams_task_init();

#endif /* CONFIG_SMP */

	ams->ams_context = &ctx;

	memset(ams->ams_context, 0, sizeof(*ams->ams_context));
	ams->ams_context->shared = &shared_ctx;

	ams_create_shared_context(&shared_ctx);

	ams->ams_context->callback_context = &ams;

	return 0;
}

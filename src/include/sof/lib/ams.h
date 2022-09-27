/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2022 Intel Corporation
 *
 * Author: Krzysztof Frydryk <krzysztofx.frydryk@intel.com>
 *
 */

#ifndef AM_SERVICE_H
#define AM_SERVICE_H

#include <errno.h>
#include <sof/schedule/task.h>
#include <sof/lib/uuid.h>
#include <sof/coherent.h>

#define AMS_INVALID_MSG_TYPE 0
#define AMS_SERVICE_UUID_TABLE_SIZE 49
#define AMS_MAX_MSG_SIZE 0x1000
#define AMS_INVALID_SLOT 0xFF
#define AMS_ANY 0xFFFF

#define AMS_ROUTING_TABLE_SIZE 41

#define AMS_SLOT_SIZE(msg) (AMS_MESSAGE_SIZE(msg) + sizeof(uint16_t) * 2)
#define AMS_MESSAGE_SIZE(msg) (sizeof(*msg) - sizeof(char) + (sizeof(char) * (msg->message_length)))

struct async_message_service **arch_ams_get(void);

/* IXC message payload -  ams_message_payload - contains the actual Async Msg payload */
struct ams_message_payload {
	uint32_t message_type_id;
	uint16_t producer_module_id;
	uint16_t producer_instance_id;
	uint32_t message_length;
	uint8_t *message;
};

struct ams_slot {
	uint16_t module_id;
	uint16_t instance_id;
	union {
		struct ams_message_payload msg;
		uint8_t msg_raw[AMS_MAX_MSG_SIZE];
	} u;
	uint32_t __aligned(PLATFORM_DCACHE_ALIGN) pad[0];
};

/* ams_msg_callback_fn - each subscriber provides this handler function for each message ID */
typedef void (*ams_msg_callback_fn)(const struct ams_message_payload *const ams_message_payload,
				    void *ctx);

/* Internal struct ams_routing_entry */
/*
 * Describes a single consumer's subscription to a single message.
 * Array of 'ams_routing_entry' structs forms AsyncMessageService's routing
 * table which allows for message dispatch.
 * If the consumer is remote (i.e. running in other domain) it's gateway handle
 * is provided, if the consumer is local it shall be set to NULL.
 */
struct ams_routing_entry {
	/* Message ID that will be routed via this entry */
	uint32_t message_type_id;
	/* Callback provided by the subscribed consumer */
	ams_msg_callback_fn consumer_callback;
	/* Additional context for consumer_callback (optional) */
	void *ctx;
	/* Subscribed consumer's Module ID */
	uint16_t consumer_module_id;
	/* Subscribed consumer's Module Instance ID */
	uint8_t consumer_instance_id;
	/* Subscribed consumer's Module core id */
	uint8_t consumer_core_id;
};

struct ams_producer {
	/* Message ID that will be routed via this entry */
	uint32_t message_type_id;
	/* Subscribed producer's Module ID */
	uint16_t producer_module_id;
	/* Subscribed producer's Module Instance ID */
	uint8_t producer_instance_id;
};

struct uuid_idx {
	uint32_t message_type_id;
	uint8_t message_uuid[UUID_SIZE];
};

struct ams_shared_context {
	/* shmid should be only used with ams_acquire/release function, not generic ones */
	struct coherent c;

	uint32_t last_used_msg_id;
	struct ams_routing_entry rt_table[AMS_ROUTING_TABLE_SIZE];
	size_t routing_table_size;
	struct ams_producer producer_table[AMS_ROUTING_TABLE_SIZE];
	size_t producer_table_size;
	struct uuid_idx uuid_table[AMS_SERVICE_UUID_TABLE_SIZE];
	size_t uuid_table_size;

	uint32_t slot_uses[CONFIG_CORE_COUNT];
	/* marks which core already processed slot */
	uint32_t slot_done[CONFIG_CORE_COUNT];

	struct ams_slot slots[CONFIG_CORE_COUNT];
};

struct ams_context {
	/* shared context must be always accessed with shared->shmid taken */
	struct ams_shared_context *shared;
	/* ams_send_ixc_fn send_message_callback; */
	void *callback_context;
};

struct async_pin_props {
	uint8_t message_type_uuid[UUID_SIZE];
};

struct ams_task {
	struct task ams_task;
	struct async_message_service *ams;
	bool is_in_do_work;
	uint32_t pending_slots;
};

struct async_message_service {
#if CONFIG_SMP
	struct ams_task ams_task;
#endif /* CONFIG_SMP */
	struct ams_context ams_context;
};

#if CONFIG_AMS
int ams_init(void);
int ams_get_message_type_id(const uint8_t *message_uuid,
			    uint32_t *message_type_id);

int ams_register_producer(uint32_t message_type_id,
			  uint16_t module_id,
			  uint16_t instance_id);

int ams_unregister_producer(uint32_t message_type_id,
			    uint16_t module_id,
			    uint16_t instance_id);

int ams_register_consumer(uint32_t message_type_id,
			  uint16_t module_id,
			  uint16_t instance_id,
			  ams_msg_callback_fn function,
			  void *ctx);

int ams_unregister_consumer(uint32_t message_type_id,
			    uint16_t module_id,
			    uint16_t instance_id,
			    ams_msg_callback_fn function);

int ams_send(const struct ams_message_payload *payload);

int ams_send_mi(const struct ams_message_payload *payload,
		uint16_t module_id, uint16_t instance_id);

int ams_send_over_ixc(struct async_message_service *ams, uint32_t slot,
		      struct ams_routing_entry *target);

int get_input_async_pin_props(struct async_message_service *ams, uint16_t module_id,
			      uint16_t instance_id,
			      uint32_t max_size,
			      uint32_t *input_count,
			      struct async_pin_props *pin_props);

int get_output_async_pin_props(struct async_message_service *ams, uint16_t module_id,
			       uint16_t instance_id,
			       uint32_t max_size,
			       uint32_t *output_count,
			       struct async_pin_props *pin_props);

#else
static inline int ams_init(void) { return 0; }
static inline int ams_get_message_type_id(const uint8_t *message_uuid,
					  uint32_t *message_type_id) { return 0; }

static inline int ams_register_producer(uint32_t message_type_id,
					uint16_t module_id,
					uint16_t instance_id) { return 0; }

static inline int ams_unregister_producer(uint32_t message_type_id,
					  uint16_t module_id,
					  uint16_t instance_id) { return 0; }

static inline int ams_register_consumer(uint32_t message_type_id,
					uint16_t module_id,
					uint16_t instance_id,
					ams_msg_callback_fn function,
					void *ctx) { return 0; }

static inline int ams_unregister_consumer(uint32_t message_type_id,
					  uint16_t module_id,
					  uint16_t instance_id,
					  ams_msg_callback_fn function) { return 0; }

static inline int ams_send(const struct ams_message_payload *payload) { return 0; }

static inline int ams_send_mi(const struct ams_message_payload *payload, uint16_t module_id,
			      uint16_t instance_id) { return 0; }

static inline int ams_send_over_ixc(struct async_message_service *ams, uint32_t slot,
				    struct ams_routing_entry *target) { return 0; }

static inline int get_input_async_pin_props(struct async_message_service *ams, uint16_t module_id,
					    uint16_t instance_id,
					    uint32_t max_size,
					    uint32_t *input_count,
					    struct async_pin_props *pin_props) { return 0; }

static inline int get_output_async_pin_props(struct async_message_service *ams, uint16_t module_id,
					     uint16_t instance_id,
					     uint32_t max_size,
					     uint32_t *output_count,
					     struct async_pin_props *pin_props) { return 0; }

#endif /* CONFIG_AMS */

#if CONFIG_SMP && CONFIG_AMS
int process_incoming_message(uint32_t slot);
#else
static inline int process_incoming_message(uint32_t slot) { return 0; }
#endif /* CONFIG_SMP && CONFIG_AMS */

#endif

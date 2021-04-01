/*
 * fw/attacks/attack.h - Declaration of the attack function
 *
 * Written 2020 by Dimitrios-Georgios Akestoridis
 * Copyright 2020 Dimitrios-Georgios Akestoridis
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#ifndef F_CPU
#define F_CPU   8000000UL
#endif

#ifndef ATTACK_H
#define	ATTACK_H

#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

#include <avr/io.h>
#include <avr/sleep.h>
#include <avr/interrupt.h>
#include <util/delay.h>
#include <assert.h>

#include "usb.h"
#include "mac.h"
#include "board.h"
#include "sernum.h"
#include "spi.h"
#include "atusb/ep0.h"
#include "at86rf230.h"

#define REJOIN_REQUEST_INTERVAL 10000
#define MAX_REJOIN_REQUEST_NUM 1000
#define MAX_ZBEE_PKT_SIZE 255
#define TC_REJOIN_PKT_SIZE 37

#define ST_SENSOR_MAC_ADDR 0x286d9700010d8ebc

enum {
	ZBEE_MAC_CMD_DATA_RQ,
	ZBEE_MAC_CMD_BEACON_RQ,
	ZBEE_MAC_CMD_BEACON_RP,
	ZBEE_NWK_CMD_REJOIN_RQ,
	ZBEE_NWK_CMD_REJOIN_RP,
	ZBEE_APS_CMD_KEY_TRANSPORT
};

typedef union {
	uint8_t addr_bytes[2];
	uint16_t addr;
}addr_16;

// Our defined data structures
typedef struct {
    uint16_t     pan;
    uint64_t     epan;
    uint16_t     short_addr;
    uint64_t     long_addr;
	uint8_t		 polling_type; // type = 2: high polling rate; type = 1: normal polling rate; type = 0: low polling rate
} ieee802154_addr;

typedef struct {
	uint8_t aack_flag;
	addr_16 target_short_addr;
	addr_16 target_pan_id;
	uint8_t dis_ack;
	uint8_t pending;
}rx_aack_config;

void send_data_request(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr);
void send_beacon_request(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr);
void send_beacon_response(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr);
void send_rejoin_request(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr);
void send_rejoin_response(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr);
void send_transport_key(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr);

void set_rx_aack(rx_aack_config* aack_config);
void send_zbee_cmd(uint8_t command, uint8_t security,
				   ieee802154_addr* dst_addr, ieee802154_addr* src_addr,
				   rx_aack_config* aack_config);

void reconnaissance_attack(void);
uint8_t capacity_attack(ieee802154_addr* hub_addr, uint64_t random_addr);
uint8_t offline_attack(ieee802154_addr* hub_addr, ieee802154_addr* zed_addr, uint64_t random_addr);
void process_trust_center_rejoin(uint8_t *rejoin_response_flag);
#endif /* !ATTACK_H */

/*
 * fw/attacks/attack.h - Declaration of the attack function
 *
 * Written 2021 by Wang Jincheng
 * Copyright 2021 Wang Jincheng
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

#define PROCESS_RX_PACKET 1

#define REJOIN_REQUEST_INTERVAL 100
#define MAX_REJOIN_REQUEST_NUM 1000
#define MAX_ZBEE_PKT_SIZE 255
#define TC_REJOIN_REQ_PKT_SIZE 27
#define TC_REJOIN_RSP_PKT_SIZE 37
#define BEACON_RQ_PKT_SIZE 8
#define DATA_RQ_PKT_SIZE   10

// MAC Addr for devices
#define ST_HUB_MAC_ADDR	   0x286d970002054a14   // SAMJIN
#define ST_SENSOR_MAC_ADDR 0x286d9700010d8ebc   // SAMJIN
#define ST_OUTLET_MAC_ADDR 0xccccccfffedbbb3e   // Silicon
#define IKEA_HUB_MAC_ADDR 0x804b50fffe4f8c81
#define IKEA_SENSOR_MAC_ADDR 0x680ae2fffe31681c // Silicon MCU
#define IKEA_BULB_MAC_ADDR 0x847127fffe410185 // Silicon MCU
#define PHILIPS_BRIDGE_MAC_ADDR  0x00178801053fab13
#define PHILIPS_BULB_MAC_ADDR   0x0017880103067f46
#define PHILIPS_SWITCH_MAC_ADDR 0x0017880108f47acc
#define XIAOMI_HUB_MAC_ADDR 0x00158d0003d43861
#define XIAOMI_HUB2_MAC_ADDR 0x588e81fffe4c8a43 // Silicon
#define XIAOMI_SWITCH_MAC_ADDR 0x00158d000322d871
#define XIAOMI_HUMAN_SENSOR_ADDR 0x00158d000632b755

#define YALE_LOCK_MAC_ADDR 0x000d6f000fed30a6

// EPAN ID
#define ST_EPAN_ID  0x0ab4da5c2ea6d3ec
#define PHILIPS_EPAN_ID 0x312c9504a155c118
#define XIAOMI_EPAN_ID 0x00158d0003d43861
#define XIAOMI2_EPAN_ID 0x6b0185760a85c757
#define IKEA_EPAN_ID 0xc6cb50753689b16d
#define REG_CHANGE_DELAY 5
#define DELAY_1 _delay_ms(1000)

enum {
	ZBEE_MAC_CMD_DATA_RQ,
	ZBEE_MAC_CMD_BEACON_RQ,
	ZBEE_MAC_CMD_BEACON_RP,
	ZBEE_MAC_CMD_ORPHAN_NOTIF,
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
	uint8_t		 polling_type; // type = 2: high polling rate; type = 1: low polling rate; type = 0: N/A
	uint8_t		 device_type;  // type = 2; ZED;			   type = 1: ZR;		type = 0: ZC
	uint8_t		 rx_when_idle; //  1: True; 0: False
	uint8_t		 beacon_update_id;
	uint8_t		 coordinator_flag;
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
void send_orphan_notification(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr);
void send_rejoin_request(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr);
void send_rejoin_response(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr);
void send_transport_key(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr);

void set_rx_aack(rx_aack_config* aack_config);
void send_zbee_cmd(uint8_t command, uint8_t security,
				   ieee802154_addr* dst_addr, ieee802154_addr* src_addr,
				   rx_aack_config* aack_config);

void reconnaissance_attack(void);
uint8_t capacity_attack(ieee802154_addr* hub_addr, uint64_t random_addr, uint8_t type);
uint8_t offline_attack(ieee802154_addr* hub_addr, ieee802154_addr* victim_addr, uint64_t random_addr);
uint8_t hijacking_attack(ieee802154_addr* hub_addr, ieee802154_addr* victim_addr, uint64_t random_addr);
#endif /* !ATTACK_H */

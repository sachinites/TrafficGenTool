#include "CommandParser/libcli.h"
#include "CommandParser/cmdtlv.h"

#define CMD_CODE_CONFIG_PKT_PROFILE_NAME 1
#define CMD_CODE_CONFIG_PKT_PROFILE_NAME_ETH_HDR_DMAC 2
#define CMD_CODE_CONFIG_PKT_PROFILE_NAME_ETH_HDR_SMAC 3
#define CMD_CODE_CONFIG_PKT_PROFILE_NAME_ETH_HDR_PROTO 4
#define CMD_CODE_CONFIG_PKT_PROFILE_NAME_IP_HDR_SIP 5
#define CMD_CODE_CONFIG_PKT_PROFILE_NAME_IP_HDR_DIP 6
#define CMD_CODE_CONFIG_PKT_PROFILE_NAME_UDP_HDR_SPORT 7
#define CMD_CODE_CONFIG_PKT_PROFILE_NAME_UDP_HDR_DPORT 8
#define CMD_CODE_CONFIG_PKT_PROFILE_NAME_TCP_HDR_SPORT 9
#define CMD_CODE_CONFIG_PKT_PROFILE_NAME_TCP_HDR_DPORT 10
#define CMD_CODE_CONFIG_PKT_PROFILE_NAME_SEND_RATE 11
#define CMD_CODE_CONFIG_PKT_PROFILE_NAME_PKT_COUNT 12
#define CMD_CODE_SHOW_PKT_PROFILE_NAME 13

static int
packet_profile_display_handler(param_t *param,
                       ser_buff_t *tlv_buf,
                       op_mode enable_or_disable) {

	int cmd_code = -1;

	cmd_code = EXTRACT_CMD_CODE(tlv_buf);

	switch(cmd_code) {

		case CMD_CODE_SHOW_PKT_PROFILE_NAME:
		break;
		default: ;
	}
	return 0;
}

static int
packet_profile_config_handler(param_t *param,
		       ser_buff_t *tlv_buf,
		       op_mode enable_or_disable) {

	int cmd_code = -1;

	cmd_code = EXTRACT_CMD_CODE(tlv_buf);

	switch(cmd_code) {
		case CMD_CODE_CONFIG_PKT_PROFILE_NAME:
		case CMD_CODE_CONFIG_PKT_PROFILE_NAME_ETH_HDR_DMAC:
		case CMD_CODE_CONFIG_PKT_PROFILE_NAME_ETH_HDR_SMAC:
		case CMD_CODE_CONFIG_PKT_PROFILE_NAME_ETH_HDR_PROTO:
		case CMD_CODE_CONFIG_PKT_PROFILE_NAME_IP_HDR_SIP:
		case CMD_CODE_CONFIG_PKT_PROFILE_NAME_IP_HDR_DIP:
		case CMD_CODE_CONFIG_PKT_PROFILE_NAME_UDP_HDR_SPORT:
		case CMD_CODE_CONFIG_PKT_PROFILE_NAME_UDP_HDR_DPORT:
		case CMD_CODE_CONFIG_PKT_PROFILE_NAME_TCP_HDR_SPORT:
		case CMD_CODE_CONFIG_PKT_PROFILE_NAME_TCP_HDR_DPORT:
		case CMD_CODE_CONFIG_PKT_PROFILE_NAME_SEND_RATE:
		case CMD_CODE_CONFIG_PKT_PROFILE_NAME_PKT_COUNT:
			break;
		default: ;
	}
	return 0;
}

static int
validate_l2_hdr_proto(char *value) {

	if (strcmp(value, "IP") == 0) return VALIDATION_SUCCESS;
	printf("Expected Values : IP\n");
	return VALIDATION_FAILED;
}

static void
init_traffic_gen_cli() {

    init_libcli();
    param_t *show   = libcli_get_show_hook();
    param_t *debug  = libcli_get_debug_hook();
    param_t *config = libcli_get_config_hook();
    param_t *clear  = libcli_get_clear_hook();
    param_t *run    = libcli_get_run_hook();

    {

	static param_t profile;
	init_param(&profile, CMD, "profile", 0, 0, INVALID, 0, "show packet profile");
	libcli_register_param(show, &profile);
	{
		static param_t profile_name;
		init_param(&profile_name, LEAF, 0, packet_profile_display_handler, 0, STRING, "profile-name", "Packet Profile Name");
		libcli_register_param(&profile, &profile_name);
		set_param_cmd_code(&profile_name, CMD_CODE_SHOW_PKT_PROFILE_NAME);
	}
    }

    {
	/* config packet profile <profile-name>*/
	static param_t packet;
	init_param(&packet, CMD, "packet", 0, 0, INVALID, 0, "packet");
	libcli_register_param(config, &packet);
	{
		static param_t profile;
		init_param(&profile, CMD, "profile", 0, 0, INVALID, 0, "packet profile");
		libcli_register_param(&packet, &profile);
		{
			static param_t profile_name;
			init_param(&profile_name, LEAF, 0, packet_profile_config_handler, 0, STRING, "profile-name", "Packet Profile Name");
			libcli_register_param(&profile, &profile_name);
			set_param_cmd_code(&profile_name, CMD_CODE_CONFIG_PKT_PROFILE_NAME);

			{
				/* config packet profile <profile-name> send-rate <rate> */
				static param_t send_rate;
				init_param(&send_rate, CMD, "send-rate", 0, 0, INVALID, 0, "Send Rate 1 pkt / N sec");
				libcli_register_param(&profile_name, &send_rate); 
				{
					static param_t send_rate_value;
					init_param(&send_rate_value, LEAF, 0, packet_profile_config_handler, 0, INT, "rate", "Send Rate"); 
					libcli_register_param(&send_rate, &send_rate_value);
					set_param_cmd_code(&send_rate_value, CMD_CODE_CONFIG_PKT_PROFILE_NAME_SEND_RATE);
				}
			}
			{
				/* config packet profile <profile-name> count <count> */
				static param_t count;
				init_param(&count, CMD, "pkt-count", 0, 0, INVALID, 0, "No of Pkts to be Sent");
				libcli_register_param(&profile_name, &count); 
				{
					static param_t count_value;
					init_param(&count_value, LEAF, 0, packet_profile_config_handler, 0, INT, "count", "No of Pkts to be Sent"); 
					libcli_register_param(&count, &count_value);
					set_param_cmd_code(&count_value, CMD_CODE_CONFIG_PKT_PROFILE_NAME_PKT_COUNT);
				}
			}
			{
					/* config packet profile <profile-name> eth-hdr */
					static param_t eth_hdr;
					init_param(&eth_hdr, CMD, "eth_hdr", 0, 0, INVALID, 0, "add ethernet hdr");
					libcli_register_param(&profile_name, &eth_hdr);
					{
						/* config packet profile <profile-name> eth-hdr dmac */
						static param_t dst_mac;
						init_param(&dst_mac, CMD, "dmac", 0, 0, INVALID, 0, "Destination MAC");
						libcli_register_param(&eth_hdr, &dst_mac);
						{
							/* config packet profile <profile-name> eth-hdr dmac <mac-addr> */
							static param_t mac;
							init_param(&mac, LEAF, 0, packet_profile_config_handler, 0, STRING, "dmac", "Destination MAC Address");
							libcli_register_param(&dst_mac, &mac);
							set_param_cmd_code(&mac, CMD_CODE_CONFIG_PKT_PROFILE_NAME_ETH_HDR_DMAC);
						}
					}
					{
						/* config packet profile <profile-name> eth-hdr smac */
						static param_t src_mac;
						init_param(&src_mac, CMD, "smac", 0, 0, INVALID, 0, "Source MAC");
						libcli_register_param(&eth_hdr, &src_mac);
						{
							/* config packet profile <profile-name> eth-hdr smac <mac-addr> */
							static param_t mac;
							init_param(&mac, LEAF, 0, packet_profile_config_handler, 0, STRING, "smac", "Source MAC Address");
							libcli_register_param(&src_mac, &mac);
							set_param_cmd_code(&mac, CMD_CODE_CONFIG_PKT_PROFILE_NAME_ETH_HDR_SMAC);
						}
					}
					{
						/* config packet profile <profile-name> eth-hdr protocol */
						static param_t proto;
						init_param(&proto, CMD, "protocol", 0, 0, INVALID, 0, "Protocol");
						libcli_register_param(&eth_hdr, &proto);
						{
							/* config packet profile <profile-name> eth-hdr protocol <proto-name> */
							static param_t proto_name;
							init_param(&proto_name, LEAF, 0, packet_profile_config_handler, validate_l2_hdr_proto, STRING, "proto", "L2 Protocol");
							libcli_register_param(&proto, &proto_name);
							set_param_cmd_code(&proto_name, CMD_CODE_CONFIG_PKT_PROFILE_NAME_ETH_HDR_PROTO);
						}
					}
				}
				{
					/* config packet profile <profile-name> ip-hdr */
					static param_t ip_hdr;
					init_param(&ip_hdr, CMD, "ip_hdr", 0, 0, INVALID, 0, "add IP hdr");
					libcli_register_param(&profile_name, &ip_hdr);
					{
						static param_t src_ip;
						init_param(&src_ip, CMD, "sip", 0, 0, INVALID, 0, "Source IP");
						libcli_register_param(&ip_hdr, &src_ip);
						{
							/* config packet profile <profile-name> eth-hdr smac <mac-addr> */
							static param_t ip;
							init_param(&ip, LEAF, 0, packet_profile_config_handler, 0, STRING, "sip", "Source IPV4 Address");
							libcli_register_param(&src_ip, &ip);
							set_param_cmd_code(&ip, CMD_CODE_CONFIG_PKT_PROFILE_NAME_IP_HDR_SIP);
						}
					}
					{
						static param_t dst_ip;
						init_param(&dst_ip, CMD, "dip", 0, 0, INVALID, 0, "Destination IP");
						libcli_register_param(&ip_hdr, &dst_ip);
						{
							/* config packet profile <profile-name> eth-hdr smac <mac-addr> */
							static param_t ip;
							init_param(&ip, LEAF, 0, packet_profile_config_handler, 0, STRING, "dip", "Destination IPV4 Address");
							libcli_register_param(&dst_ip, &ip);
							set_param_cmd_code(&ip, CMD_CODE_CONFIG_PKT_PROFILE_NAME_IP_HDR_DIP);
						}
					}
				}
				{
					/* config packet profile <profile-name> udp-hdr */
					static param_t udp_hdr;
					init_param(&udp_hdr, CMD, "udp-hdr", 0, 0, INVALID, 0, "add UDP hdr");
					libcli_register_param(&profile_name, &udp_hdr);
					{
						static param_t src_port;
						init_param(&src_port, CMD, "sport", 0, 0, INVALID, 0, "Source Port No");
						libcli_register_param(&udp_hdr, &src_port);
						{
							/* config packet profile <profile-name> udp-hdr sport <port no> */
							static param_t port;
							init_param(&port, LEAF, 0, packet_profile_config_handler, 0, INT, "sport", "Source Port No");
							libcli_register_param(&src_port, &port);
							set_param_cmd_code(&port, CMD_CODE_CONFIG_PKT_PROFILE_NAME_UDP_HDR_SPORT);
						}
					}
					{
						static param_t dst_port;
						init_param(&dst_port, CMD, "dport", 0, 0, INVALID, 0, "Destination Port No");
						libcli_register_param(&udp_hdr, &dst_port);
						{
							/* config packet profile <profile-name> udp-hdr dport <port no> */
							static param_t port;
							init_param(&port, LEAF, 0, packet_profile_config_handler, 0, INT, "dport", "Destination Port No");
							libcli_register_param(&dst_port, &port);
							set_param_cmd_code(&port, CMD_CODE_CONFIG_PKT_PROFILE_NAME_UDP_HDR_DPORT);
						}
					}
				}
				{
					/* config packet profile <profile-name> tcp-hdr */
					static param_t tcp_hdr;
					init_param(&tcp_hdr, CMD, "tcp-hdr", 0, 0, INVALID, 0, "add TCP hdr");
					libcli_register_param(&profile_name, &tcp_hdr);	
					{
						static param_t src_port;
						init_param(&src_port, CMD, "sport", 0, 0, INVALID, 0, "Source Port No");
						libcli_register_param(&tcp_hdr, &src_port);
						{
							/* config packet profile <profile-name> tcp-hdr sport <port no> */
							static param_t port;
							init_param(&port, LEAF, 0, packet_profile_config_handler, 0, INT, "sport", "Source Port No");
							libcli_register_param(&src_port, &port);
							set_param_cmd_code(&port, CMD_CODE_CONFIG_PKT_PROFILE_NAME_TCP_HDR_SPORT);
						}
					}
					{
						static param_t dst_port;
						init_param(&dst_port, CMD, "dport", 0, 0, INVALID, 0, "Destination Port No");
						libcli_register_param(&tcp_hdr, &dst_port);
						{
							/* config packet profile <profile-name> tcp-hdr dport <port no> */
							static param_t port;
							init_param(&port, LEAF, 0, packet_profile_config_handler, 0, INT, "dport", "Destination Port No");
							libcli_register_param(&dst_port, &port);
							set_param_cmd_code(&port, CMD_CODE_CONFIG_PKT_PROFILE_NAME_TCP_HDR_DPORT);
						}
					}
				}	
			}
	}
    }
    support_cmd_negation(config);
}

int
main(int argc, char **argv) {

	init_traffic_gen_cli();
	start_shell();
	return 0;
}

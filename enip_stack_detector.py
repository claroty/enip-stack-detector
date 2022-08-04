import socket
import struct
import sys
from construct import * # construct==2.9.45

if len(sys.argv) != 2:
	print("Usage: {} IP_ADDR".format(sys.argv[0]))
	sys.exit(1)
HOST_IP = sys.argv[1]
HOST_PORT = 44818

###################
### ENIP Header ###
###################
# Commands
ENIP_CMD_NOP = 0x0000
ENIP_CMD_LIST_TARGETS = 0x0001
ENIP_CMD_LISTSERVICES = 0x0004
ENIP_CMD_LISTIDENTITY = 0x0063
ENIP_CMD_LISTINTERFACES = 0x0064
ENIP_CMD_REGISTERSESSION = 0x0065       # TCP only
ENIP_CMD_UNREGISTERSESSION = 0x0066     # TCP only
ENIP_CMD_SENDRRDATA = 0x006F            # TCP only
ENIP_CMD_SENDUNITDATA = 0x0070          # TCP only; PCCC
ENIP_CMD_INDICATESTATUS = 0x0072
ENIP_CMD_CANCEL = 0x0073

########################
### Command Specific ###
########################
# Command Specific (type ID)
TYPE_ID_NULL = 0x0000
TYPE_ID_LIST_IDENT_RESPONSE = 0x000C
TYPE_ID_CONNECTION_BASED = 0x00A1
TYPE_ID_CONNECTED_TRANSPORT_PACKET = 0x00B1
TYPE_ID_UNCONNECTED_MESSAGE = 0x00B2
TYPE_ID_LISTSERVICES_RESPONSE = 0x0100
TYPE_ID_SOCKADDR_INFO_ORIG_TARGET = 0x8000
TYPE_ID_SOCKADDR_INFO_TARGET_ORIG = 0x8001
TYPE_ID_SEQUENCED_ADDRESS = 0x8002
TYPE_ID_CIP_SECURITY_INFORMATION = 0x0086

########################
##### List Identity ####
########################
# status is a bit encoded word
LIST_IDENT_STATUS_OWNED = 0x0001
LIST_IDENT_STATUS_CONFIGURED = 0x0004
LIST_IDENT_STATUS_EXTENDED_DEVICE_STATUS = 0x00F0
LIST_IDENT_STATUS_MINOR_RECOVERABLE_FAULT = 0x0100
LIST_IDENT_STATUS_MINOR_UNRECOVERABLE_FAULT = 0x0200
LIST_IDENT_STATUS_MAJOR_RECOVERABLE_FAULT = 0x0400
LIST_IDENT_STATUS_MAJOR_UNRECOVERABLE_FAULT = 0x0800
LIST_IDENT_STATUS_EXTENDED_DEVICE_STATUS2 = 0xF000
# states
LIST_IDENT_STATE_NONEXISTENT = 0x00
LIST_IDENT_STATE_SELF_TESTING = 0x01
LIST_IDENT_STATE_STANDBY = 0x02
LIST_IDENT_STATE_OPERATIONAL = 0x03
LIST_IDENT_STATE_RECOVERABLE_FAULT = 0x04
LIST_IDENT_STATE_UNRECOVERABLE_FAULT = 0x05
LIST_IDENT_STATE_DEFAULT = 0xFF


##########################################
################## DATA ##################
##########################################
IP_ADDRESS_V4 = ExprAdapter(Byte[4],
    decoder = lambda obj,ctx: "{0}.{1}.{2}.{3}".format(*obj),
    encoder = lambda obj,ctx: [int(x) for x in obj.split(".")],
)

# b"\x63\x00\x33\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x0c\x00\x2d\x00\x01\x00\x00\x02\xaf\x12\x0a\x01\x1e\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x0c\x00\x3a\x00\x05\x01\x60\x00\x9d\x04\xc0\x9c\x0b\x31\x37\x35\x36\x2d\x45\x4e\x42\x54\x2f\x41\x03"
LIST_IDENTITY_REPLY = Struct(
			"vendor_id" / Int16ul,
			"device_type" / Int16ul,
			"product_code" / Int16ul,
			"major_revision" / Byte,
			"minor_revision" / Byte,
			"status" / Int16ul,
			"serial" / Int32ul,
			"product_name" / PascalString(Byte, "utf8"),
			#"state" / Byte,
			)

##########################################
########## SPECIFIC COMMANDS #############
##########################################
ENIP_SOCKET_ADDRESS = Struct (
	"sin_family" / Int16ub,
	"sin_port" / Int16ub,
	"sin_addr" / IP_ADDRESS_V4,
	"sin_zero" / Int64ub,
)

ENIP_COMMAND_SPECIFIC = Struct(
				"items" / PrefixedArray(Int16ul, Struct(
					"type_id" / Int16ul,
					"data" / Prefixed(Int16ul, Switch(this.type_id,
						{
							TYPE_ID_NULL: Struct(),
							TYPE_ID_CONNECTION_BASED: Struct("connection_id" / Int32ul),
							TYPE_ID_CONNECTED_TRANSPORT_PACKET: Struct("sequence" / Int16ul, "data" / GreedyBytes),
							TYPE_ID_UNCONNECTED_MESSAGE: Struct("data" / GreedyBytes),
							TYPE_ID_LIST_IDENT_RESPONSE: Struct("version" / Int16ul, "sender_context" / ENIP_SOCKET_ADDRESS, "list_identity" / Embedded(LIST_IDENTITY_REPLY)),
							TYPE_ID_LISTSERVICES_RESPONSE: Struct("protocol_version" / Int16ul, "capability_flags" / Int16ul, "name" / GreedyBytes),
						}))
				)))


ENIP_UDP_COMMAND_SPECIFIC_LIST_IDENTITY = Struct(
			"command_specific" / ENIP_COMMAND_SPECIFIC,
			"version" / Int16ul,
			"sender_context" / ENIP_SOCKET_ADDRESS,
			"list_identity" / Embedded(LIST_IDENTITY_REPLY)
			)
ENIP_TCP_COMMAND_SPECIFIC_RR_DATA = Struct(
				"interface_handle" / Default(Int32ul, 0),
				"timeout" / Default(Int16ul, 0xff),
				"command_specific" / ENIP_COMMAND_SPECIFIC,
			)
ENIP_TCP_COMMAND_SPECIFIC_UNIT_DATA = ENIP_TCP_COMMAND_SPECIFIC_RR_DATA

ENIP_TCP_COMMAND_SPECIFIC_REGISTER_SESSION = Struct(
				"protocol_version" / Default(Int16ul, 1),
				"option" / Default(Int16ul, 0),
				"more_data" / Default(GreedyBytes, b"")
			)
##########################################
################# HEADERS  ###############
##########################################
ENIP_HEADER = Struct(
				"command" / Int16ul,
				"length" / Default(Int16ul, 0),
				"session" / Default(Int32ul, 0),
				"status" / Default(Int32ul, 0),
				"sender_context" / Default(Int64ul, 0),
				"options" / Default(Int32ul, 0),
				"more_data" / Bytes(this.length)
			)

ENIP_HEADER_SPECIAL = Struct(
				"command" / Int16ul,
				"length" / Default(Int16ul, 0),
				"session" / Default(Int32ul, 0),
				"status" / Default(Int32ul, 0),
				"sender_context" / Default(Int64ul, 0),
				"options" / Default(Int32ul, 0),
				"more_data" / GreedyBytes
			)



##########################################
################### Helpers ##############
##########################################
def h2b(d):
	return d.replace(" ", "").decode("hex")

def size2b(d, in_words=False):
	data_len = len(d)/2 if in_words else len(d)
	return struct.pack("<B", data_len)

def size2h(d, in_words=False):
	data_len = len(d)/2 if in_words else len(d)
	return struct.pack("<H", data_len)


##########################################
############## BUILD PACKETS #############
##########################################
# Build an ENIP TCP RRData packet
# Example for basic ENIP RRData packet: b'o\x00\x10\x00\x00\xc0\x00\x00\x00\x00\x00\x00=x\x01\x00\x80\xa26\x02\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00\x02\x00\x00\x00\x00\x00\xb2\x00\x04\x00\xDATA'
def build_enip_tcp_rr_data(rr_data, sender_context, session, options=0):
	command_specific = ENIP_COMMAND_SPECIFIC.build(dict(items=[dict(type_id=TYPE_ID_NULL, data=dict()), dict(type_id=TYPE_ID_UNCONNECTED_MESSAGE, data=dict(data=rr_data))]))
	enip_tcp_rr_data = ENIP_TCP_COMMAND_SPECIFIC_RR_DATA.build(dict(command_specific=ENIP_COMMAND_SPECIFIC.parse(command_specific)))
	enip_header = ENIP_HEADER.build(dict(command=ENIP_CMD_SENDRRDATA, length=len(enip_tcp_rr_data), session=session, sender_context=sender_context, options=options, more_data=enip_tcp_rr_data))
	return enip_header

##########################################
# Build an ENIP TCP UnitData packet
def build_enip_tcp_unit_data(unit_data, sender_context, session, sequence, connection_id, options=0):
	command_specific = ENIP_COMMAND_SPECIFIC.build(dict(items=[dict(type_id=TYPE_ID_CONNECTION_BASED, data=dict(connection_id=connection_id)),
		dict(type_id=TYPE_ID_CONNECTED_TRANSPORT_PACKET, data=dict(sequence=sequence, data=unit_data))]))
	enip_tcp_unit_data = ENIP_TCP_COMMAND_SPECIFIC_UNIT_DATA.build(dict(command_specific=ENIP_COMMAND_SPECIFIC.parse(command_specific)))
	enip_header = ENIP_HEADER.build(dict(command=ENIP_CMD_SENDUNITDATA, length=len(enip_tcp_unit_data), session=session, sender_context=sender_context, options=options, more_data=enip_tcp_unit_data))
	return enip_header

# Build an ENIP TCP Register Session
def build_enip_tcp_register_session(sender_context, options=0):
	register_session = ENIP_TCP_COMMAND_SPECIFIC_REGISTER_SESSION.build(dict())
	enip_packet = ENIP_HEADER.build(dict(command=ENIP_CMD_REGISTERSESSION, length=len(register_session), sender_context=sender_context, options=options, more_data=register_session))
	return enip_packet

# Build an ENIP TCP List Services
def build_enip_tcp_list_services(sender_context, options=0):
	enip_packet = ENIP_HEADER.build(dict(command=ENIP_CMD_LISTSERVICES, length=0, sender_context=sender_context, options=options, more_data=b""))
	return enip_packet

# Builds an ENIP request buffer (e.g. Identity request payload: b"\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
def build_enip_empty_request(command, session=0):
	return ENIP_HEADER.build(dict(command=command, length=0, session=session, sender_context=0, more_data=b""))


##########################################
############## PARSE PACKETS #############
##########################################
# Parse ENIP UDP packet
def parse_enip_udp_packet_identity_resp(enip_packet, item_id=TYPE_ID_LIST_IDENT_RESPONSE):
	enip_packet_parsed = ENIP_HEADER.parse(enip_packet)
	if enip_packet_parsed.command == ENIP_CMD_LISTIDENTITY:
		list_items = ENIP_COMMAND_SPECIFIC.parse(enip_packet_parsed.more_data)["items"]
		for item in list_items:
			# Item must be identity response
			if item.type_id == item_id:
				return item.data
	# Could not find any ENIP Identity response item
	return None

def is_cip_secure_compatible(enip_identity_packet):
	try:
		enip_secure_itme_parsed = parse_enip_udp_packet_identity_resp(enip_packet=enip_identity_packet, item_id=TYPE_ID_CIP_SECURITY_INFORMATION)
		return enip_secure_itme_parsed.security_profiles.cip_integrity_profile or enip_secure_itme_parsed.security_profiles.cip_authorization_profile or enip_secure_itme_parsed.security_profiles.enip_confidentiality_profile or enip_secure_itme_parsed.security_profiles.enip_integrity_profile
	except ENIPParseException as e:
		pass
	return False


##########################################
################## SOCKET ################
##########################################
### TCP ###
def create_tcp_socket(ip, port):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(5.0)
	sock.connect((ip, port))
	return sock

def tcp_send_recv(sock, data):
	sock.sendall(data)
	return sock.recv(1024)

### UDP ###
def create_udp_socket(ip, port):
	sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
	sock.bind(("0.0.0.0", 53432))
	return sock

def udp_send_recv(sock, dest_tuple, data):
	sock.sendto(data, dest_tuple)
	return sock.recvfrom(1024)[0]


##########################################
############## ENIP FUNCTIONS ############
##########################################
def create_enip_session(sock, sender_context, options):
	pkt_session_buffer = build_enip_tcp_register_session(sender_context, options)
	pkt_resp = tcp_send_recv(sock=sock, data=pkt_session_buffer)
	return ENIP_HEADER.parse(pkt_resp)



##########################################
################# TESTS ##################
##########################################
def test_log(test_name, did_pass, used_val=None):
	char_pass = "V" if did_pass else "X"
	used_value = " (Used value: {})".format(used_val) if used_val else ""
	print("[ {} ]: {}{}".format(char_pass, test_name, used_value))



# Will generate X sessions and check if they are all sequential by Y
def test_enip_register_session_sequential(seq_jump=1, number_of_sessions_to_create=3):
	test_result = True
	sender_context_test = 0x12341234
	options_normal = 0
	seq_add_val = seq_jump
	resp_enip = create_enip_session(sock=create_tcp_socket(ip=HOST_IP, port=HOST_PORT), sender_context=sender_context_test, options=options_normal)
	base_session = resp_enip.session
	for i in range(number_of_sessions_to_create):
		sock = create_tcp_socket(ip=HOST_IP, port=HOST_PORT)
		resp_enip = create_enip_session(sock=sock, sender_context=sender_context_test, options=options_normal)
		sock.close()
		if base_session + seq_add_val != resp_enip.session:
			test_result = False
			break
		base_session += seq_add_val
	test_log("ENIP Register Session Number Sequential", test_result, hex(seq_jump))
	return test_result


# Tests if allowed to register session with random option num
def test_enip_register_session_bad_options(options_non_zero=1):
	test_result = False
	sender_context_test = 0x12341234
	try:
		resp_enip = create_enip_session(sock=create_tcp_socket(ip=HOST_IP, port=HOST_PORT), sender_context=sender_context_test, options=options_non_zero)
		if resp_enip.session != 0:
			test_result = True
	except socket.timeout:
		test_result = False	
	test_log("ENIP Can Register Session with Bad Options", test_result, options_non_zero)
	return test_result


# Tests if possible to register session with bad length.
#	some stacks only allow lenght of 4 bytes.
def test_enip_register_session_bad_length(bad_length=3):
	test_result = False
	sender_context_test = 0x12341234
	options_normal = 0
	try:
		register_session = ENIP_TCP_COMMAND_SPECIFIC_REGISTER_SESSION.build(dict())
		pkt_session_buffer = ENIP_HEADER_SPECIAL.build(dict(command=ENIP_CMD_REGISTERSESSION, length=bad_length, sender_context=sender_context_test, options=options_normal, more_data=register_session))
		pkt_resp = tcp_send_recv(sock=create_tcp_socket(ip=HOST_IP, port=HOST_PORT), data=pkt_session_buffer)
		pkt_resp_parsed = ENIP_HEADER.parse(pkt_resp)
		if pkt_resp_parsed.session != 0:
			test_result = True
	except socket.timeout:
		test_result = False
	except Exception as e:
		test_result = False
	test_log("ENIP Can Register Session with Bad Length", test_result, bad_length)
	return test_result


# Tests consts of list services
def test_enip_list_services():
	sender_context_test = 0x12341234
	options_normal = 0
	pkt_list_services_buffer = build_enip_tcp_list_services(sender_context=sender_context_test, options=options_normal)
	pkt_resp = tcp_send_recv(sock=create_tcp_socket(ip=HOST_IP, port=HOST_PORT), data=pkt_list_services_buffer)
	pkt_resp_parsed = ENIP_HEADER.parse(pkt_resp)
	pkt_resp_items_parsed = ENIP_COMMAND_SPECIFIC.parse(pkt_resp_parsed.more_data)
	item =  pkt_resp_items_parsed.get("items")[0].data
	is_ver_1 = item.protocol_version == 1
	is_name_comm_with_space = item.name == b'Communications \x00'
	is_name_comm_with_single_null = item.name == b'Communications\x00'
	is_name_comm_with_nulls = item.name == b'Communications\x00\x00'
	is_name_comm_upper_with_nulls = item.name == b'COMMUNICATIONS\x00\x00'
	are_reserved_bits_clear = (item.capability_flags & 0xfedf ) == 0
	test_log("ENIP List Services Protocol Version is 1", is_ver_1)
	test_log("ENIP List Services Name is \"Communications \\x00\" (with space)", is_name_comm_with_space)
	test_log("ENIP List Services Name is \"Communications\\x00\" (with single null (bug))", is_name_comm_with_single_null)
	test_log("ENIP List Services Name is \"Communications\\x00\\x00\" (with nulls)", is_name_comm_with_nulls)
	test_log("ENIP List Services Name is \"COMMUNICATIONS\\x00\\x00\" (upper with nulls)", is_name_comm_upper_with_nulls)
	if not is_name_comm_with_space and not is_name_comm_with_nulls and not is_name_comm_upper_with_nulls and not is_name_comm_with_single_null:
		print("		[!] received non-standard service name: {}".format(item.name))
	#  bits 0 - 4 : reserved
	#  bit 5 : 1 = CIP over TCP supported, else 0
	#  bits 6 - 7 : reserved
	#  bit 8 : 1 = Supports CIP Class 0/1 UDP (I/O)
	#  bits 9 - 15 : reserved
	test_log("ENIP List Services Name Capability Flags Reserved Bit Are Empty", are_reserved_bits_clear)
	return is_ver_1, is_name_comm_with_space, is_name_comm_with_single_null, is_name_comm_with_nulls, is_name_comm_upper_with_nulls, are_reserved_bits_clear


# Tests if List Targets command is supported
def test_enip_list_targets():
	test_result = False
	sender_context_test = 0x12341234
	options_normal = 0
	sock = create_tcp_socket(ip=HOST_IP, port=HOST_PORT)
	pkt_nop_buffer = ENIP_HEADER_SPECIAL.build(dict(command=ENIP_CMD_LIST_TARGETS, length=0, sender_context=sender_context_test, options=options_normal, more_data=b''))
	pkt_resp = tcp_send_recv(sock=sock, data=pkt_nop_buffer)
	if pkt_resp:
		pkt_resp_parsed = ENIP_HEADER.parse(pkt_resp)
		if pkt_resp_parsed.more_data:
			test_result = True
	test_log("ENIP Is List Targets Supported", test_result)
	return test_result


# CIP Forward open
def cip_forward_open_request(bad_flags=False):
	supports_cip_forward_open = False
	cip_status = None
	o2t = None
	t2o = None
	### Build message ###
	sender_context = 0x1234432112344321
	# Get ENOP Session
	sock = create_tcp_socket(ip=HOST_IP, port=HOST_PORT)
	resp_enip = create_enip_session(sock=sock, sender_context=sender_context, options=0)
	enip_session = resp_enip.session
	cip_connection_id = 0x10001001
	# CIP Data
	service = h2b("54")
	cip_class_path = h2b("20 06 24 01") # Connection Manager
	cip_class_path_size = size2b(cip_class_path, True)
	cip_data_1 = service + cip_class_path_size + cip_class_path

	priority_and_tick_time = h2b("07")
	timeout_ticks = h2b("01")
	o_t_network_connection_id = h2b("00 00 00 00")#h2b("6d eb 00 80")
	t_o_network_connection_id = h2b("00 00 00 00")#h2b("80 fe eb 6c")
	connection_serial_number = h2b("02 01")
	vendor_id = h2b("4d 00")
	originator_serial_number = h2b("04 03 02 01")
	connection_timeout_multiplier = h2b("01")
	reserved1 = h2b("00 00")#h2b("00 00")
	reserved2 = h2b("00")#h2b("00")
	o_t_pri = h2b("04 03 02 01")
	o_t_network_connection_parameters = h2b("f4 43")#h2b("f4 43")
	t_o_pri = h2b("04 03 02 01")
	t_o_network_connection_parameters = h2b("f4 43")#h2b("f4 43")
	flags = h2b("a3")#h2b("a3")# direction=1, trigger=2, cm_class=3 
	if bad_flags:
		flags = h2b("f3")#h2b("a3")# direction=1, trigger=2, cm_class=3 

	# -- Normal forward open --
	path_size = h2b("02")
	path = h2b("20 02 24 01")

	cip_data = cip_data_1 + priority_and_tick_time + timeout_ticks + o_t_network_connection_id + t_o_network_connection_id + connection_serial_number + vendor_id + originator_serial_number + connection_timeout_multiplier + reserved1 + reserved2 + o_t_pri + o_t_network_connection_parameters + t_o_pri + t_o_network_connection_parameters + flags + path_size + path

	# Command Specific Data
	command_specifc_data = b""
	command_specifc_data += h2b("00 00 00 00") 					# 
	command_specifc_data += h2b("ff 00") 							# Timeout
	command_specifc_data += h2b("02 00") 							# Items count
	command_specifc_data += h2b("00 00 00 00") 					# Item #1: Null address Item
	command_specifc_data += h2b("b2 00") + size2h(cip_data)			# Item #2: Unconnected Data Item
	# ENIP RR data
	overall_cip_data = command_specifc_data + cip_data
	enip_rr_data_buffer = ENIP_HEADER.build(dict(command=ENIP_CMD_SENDRRDATA, length=len(overall_cip_data), session=enip_session, sender_context=sender_context, more_data=overall_cip_data))

	### Send message ###
	try:
		pkt_resp = tcp_send_recv(sock=sock, data=enip_rr_data_buffer)
		if pkt_resp:
			pkt_resp_parsed = ENIP_HEADER.parse(pkt_resp)
			if pkt_resp_parsed.more_data:
				supports_cip_forward_open = True
				cip_status = struct.unpack("<H", pkt_resp_parsed.more_data[18:20])[0]
				# Forward open was successful
				if cip_status == 0:
					o2t, t2o = struct.unpack("<II", pkt_resp_parsed.more_data[20:28])
	except Exception as e:
		pass
	return supports_cip_forward_open, cip_status, o2t, t2o


def test_cip_forward_open():
	supports_cip_forward_open = False
	allows_multiple_cip_forward_open_request_on_zero = False
	is_o2t_sequencial_by_1 = False
	is_t2o_zero = False
	is_forward_open_with_bad_flags = False

	supports_cip_forward_open_1, cip_status_1, o2t_1, t2o_1 = cip_forward_open_request()
	if supports_cip_forward_open_1 and cip_status_1 == 0:
		supports_cip_forward_open_2, cip_status_2, o2t_2, t2o_2 = cip_forward_open_request()
		supports_cip_forward_open_3, cip_status_3, o2t_3, t2o_3 = cip_forward_open_request()
		supports_cip_forward_open_bad_flags, cip_status_bad_flags, o2t_bad_flags, t2o_bad_flags = cip_forward_open_request(bad_flags=True)

		supports_cip_forward_open = True

		# Check T2O zero
		if t2o_1 == 0:
			is_t2o_zero = True

		# Check if CIP Forward open supported
		if supports_cip_forward_open_1 and cip_status_1 == 0 and\
		supports_cip_forward_open_2 and cip_status_2 == 0 and\
		supports_cip_forward_open_3 and cip_status_3 == 0:
			allows_multiple_cip_forward_open_request_on_zero = True

			# Check if O2T is sequencial by 1
			if o2t_1 + 1 == o2t_2 and\
			 o2t_2 + 1 == o2t_3:
				is_o2t_sequencial_by_1 = True

			# Check if CIP forward works with bad flags
			if supports_cip_forward_open_bad_flags and cip_status_bad_flags == 0:
				is_forward_open_with_bad_flags = True

	test_log("CIP Forward Open is supported", supports_cip_forward_open)
	test_log("CIP Forward Open allows multiple requests for connection id 0", allows_multiple_cip_forward_open_request_on_zero)
	test_log("CIP Forward Open is O2T Sequential by 1", is_o2t_sequencial_by_1)
	test_log("CIP Forward Open is T2O zero", is_t2o_zero)
	test_log("CIP Forward Open can open with bad connection flags", is_forward_open_with_bad_flags)

	return supports_cip_forward_open, allows_multiple_cip_forward_open_request_on_zero, is_o2t_sequencial_by_1, is_t2o_zero, is_forward_open_with_bad_flags


def get_enip_list_identity():
	sender_context_test = 0x12341234
	options_normal = 0
	pkt_list_identity_buffer = build_enip_empty_request(command=ENIP_CMD_LISTIDENTITY)
	pkt_resp = tcp_send_recv(sock=create_tcp_socket(ip=HOST_IP, port=HOST_PORT), data=pkt_list_identity_buffer)
	parsed_identity = parse_enip_udp_packet_identity_resp(pkt_resp)
	print("==============Device================")
	print("[!] {}: {} (vendor:{} type: {}, v{}.{})".format(HOST_IP, parsed_identity.product_name, parsed_identity.vendor_id, parsed_identity.device_type, parsed_identity.major_revision, parsed_identity.minor_revision))
	print("====================================")
	print("")
	return True


def main():
	print("-----------------------------------------")
	print("--- EtherNet/IP & CIP Stack Detector ----")
	print("-----------------------------------------")
	print("------By Sharon Brizinov @ Claroty-------")
	print("-----------------v0.8--------------------")
	print("")
	can_start_test = True
	try:
		get_enip_list_identity()
	except Exception as e:
		print(e)
		can_start_test = False
		print("[!] Failed to query list identity. Can not perform fingerprinting.")
	if can_start_test:
		print("================Tests===============")
		is_register_session_sequential_0x1 = test_enip_register_session_sequential(0x1)
		is_register_session_sequential_0x10 = test_enip_register_session_sequential(0x10)
		is_register_session_sequential_0x100 = test_enip_register_session_sequential(0x100)
		is_register_session_sequential_0x1000 = test_enip_register_session_sequential(0x1000)
		is_register_session_sequential_0x10000 = test_enip_register_session_sequential(0x10000)
		can_register_session_bad_options = test_enip_register_session_bad_options()
		can_register_session_bad_length = test_enip_register_session_bad_length()
		is_enip_list_targets_supported = test_enip_list_targets()
		is_ver_1, is_name_comm_with_space, is_name_comm_with_single_null, is_name_comm_with_nulls, is_name_comm_upper_with_nulls, are_reserved_bits_clear = test_enip_list_services()
		supports_cip_forward_open, allows_multiple_cip_forward_open_request_on_zero, is_o2t_sequencial_by_1, is_t2o_zero, is_forward_open_with_bad_flags = test_cip_forward_open()
		print("====================================")
		print("")

		list_result = [is_register_session_sequential_0x1, is_register_session_sequential_0x10, is_register_session_sequential_0x100, is_register_session_sequential_0x1000, is_register_session_sequential_0x10000, can_register_session_bad_options, can_register_session_bad_length, is_enip_list_targets_supported, is_ver_1, is_name_comm_with_space, is_name_comm_with_single_null, is_name_comm_with_nulls, is_name_comm_upper_with_nulls, are_reserved_bits_clear, supports_cip_forward_open, allows_multiple_cip_forward_open_request_on_zero, is_o2t_sequencial_by_1, is_t2o_zero, is_forward_open_with_bad_flags]
		str_result = "".join(["1" if a else "0" for a in list_result])

		# Stacks	
		print("==============Results===============")
		if str_result == "1000000011000111111":
			res = "RTAutomation (sig: '{}')".format(str_result)

		elif str_result == "0010000110010111011":
			res = "Rockwell 1756-EN2TR/A (sig: '{}')".format(str_result)

		elif str_result == "1000000010010111110":
			res = "Rockwell 1756-L81E/B (sig: '{}')".format(str_result)

		elif str_result == "1000001110010110010":
			res = "Rockwell RSLinx (sig: '{}')".format(str_result)

		elif str_result == "0000000110010110010":
			res = "Rockwell LC 20/50 (sig: '{}')".format(str_result)

		elif str_result == "0000010110100100000" or str_result == "0000010110100111011":
			res = "CPPPO (e.g. conpot) (sig: '{}')".format(str_result)

		elif str_result == "0000000110010111000":
			res = "Rockwell 1763/1766 (sig: '{}')".format(str_result)
		
		elif str_result == "0000000010010110010":
			res = "Rockwell 1769 (sig: '{}')".format(str_result)

		elif str_result == "0000010110010111011":
			res = "Rockwell SoftLogix5800 Emulator (sig: '{}')".format(str_result)

		elif str_result == "1000011110010110010":
			res = "Rockwell PanelView Plus (sig: '{}')".format(str_result)

		elif str_result == "0010010110010111011":
			res = "Rockwell SLC/PLC5 (sig: '{}')".format(str_result)

		elif str_result == "0000000010010111000":
			res = "No-Name-Yet (sig: '{}')".format(str_result)

		elif str_result == "0000001010010111110":
			res = "OpENer Stack (sig: '{}')".format(str_result)
		else:
			res = "UNKNOWN (sig: '{}')".format(str_result)
		print("[!] EtherNet/IP & CIP Stack: {}".format(res))
		print("====================================")
main()

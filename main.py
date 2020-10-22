from scapy.compat import raw
from scapy.utils import rdpcap


sap_file = "SAP.txt"
ip_protocols_file = "IP_Protocols.txt"
tcp_file = "TCP_Ports.txt"
udp_file = "UDP_Ports.txt"
ether_types_file = "EtherTypes.txt"
icmp_file = "ICMP_Types.txt"


def transform_bytes(old_string):
    new_string = ""
    i = 0

    for char in old_string:
        if i % 2 == 0 and i != 0:
            new_string += " "

        new_string += char
        i += 1

    return new_string


def transform_frame(old_string):
    string_list = []
    new_string = ""
    i = 0

    for char in old_string:
        if i % 32 == 0 and i != 0:
            string_list.append(transform_bytes(new_string))
            new_string = ""

        new_string += char
        i += 1

    if new_string != "":
        string_list.append(transform_bytes(new_string))

    return string_list


def hex_to_dec(hex_string):
    return int(hex_string, 16)


def get_dst_mac(packet_hex):
    return packet_hex[0:12]


def get_src_mac(packet_hex):
    return packet_hex[12:24]


def get_data_length_hex(packet_hex):
    return packet_hex[24:28]


def get_sap_hex(packet_hex):
    return packet_hex[28:30]


def get_snap_ether_type(packet_hex):
    return packet_hex[40:44]


def identify_hex(my_hex, hex_identification_file_name):
    hex_identification_file = open("Data/" + hex_identification_file_name, "r")

    my_hex_identified = None
    for line in hex_identification_file:
        words = line.split()
        if words[0] == my_hex:
            my_hex_identified = words[1]

    hex_identification_file.close()

    return my_hex_identified


def ipv4_get_src_ip_hex(packet_hex):
    return packet_hex[24:32]


def ipv4_get_dst_ip_hex(packet_hex):
    return packet_hex[32:40]


def arp_get_src_ip_hex(packet_hex):
    return packet_hex[28:36]


def arp_get_dst_ip_hex(packet_hex):
    return packet_hex[48:56]


def hex_to_ip(ip_hex):
    ip_hex1 = ip_hex[0:2]
    ip_hex2 = ip_hex[2:4]
    ip_hex3 = ip_hex[4:6]
    ip_hex4 = ip_hex[6:8]

    ip_dec1 = hex_to_dec(ip_hex1)
    ip_dec2 = hex_to_dec(ip_hex2)
    ip_dec3 = hex_to_dec(ip_hex3)
    ip_dec4 = hex_to_dec(ip_hex4)

    ip = str(ip_dec1) + "." + str(ip_dec2) + "." + str(ip_dec3) + "." + str(ip_dec4)

    return ip


def ipv4_get_protocol(packet_hex):
    return packet_hex[18:20]


def tcp_get_src_port_hex(packet_hex):
    return packet_hex[0:4]


def tcp_get_dst_port_hex(packet_hex):
    return packet_hex[4:8]


def tcp_get_flag_hex(packet_hex):
    return packet_hex[24:28]


def udp_get_src_port_hex(packet_hex):
    return packet_hex[0:4]


def udp_get_dst_port_hex(packet_hex):
    return packet_hex[4:8]


def icmp_get_type_hex(packet_hex):
    return packet_hex[0:2]


class Sap:
    name: str

    def __init__(self, name):
        self.name = name


class EtherType:
    name: str

    def __init__(self, name):
        self.name = name


class ARP(EtherType):
    src_ip: str
    dst_ip: str

    def __init__(self):
        super().__init__("ARP")


class IPv4(EtherType):
    src_ip: str
    dst_ip: str

    def __init__(self):
        super().__init__("IPv4")


class TransportProtocol:
    name: str

    def __init__(self, name):
        self.name = name


class TCP(TransportProtocol):
    src_port: int
    dst_port: int

    src_socket: str
    dst_socket: str

    flag: int

    def __init__(self, src_port, dst_port, src_ip, dst_ip, flag):
        super().__init__("TCP")

        self.src_port = src_port
        self.dst_port = dst_port

        self.src_socket = src_ip + ":" + str(src_port)
        self.dst_socket = dst_ip + ":" + str(dst_port)

        self.flag = flag


class UDP(TransportProtocol):
    src_port: int
    dst_port: int

    def __init__(self, src_port, dst_port):
        super().__init__("UDP")

        self.src_port = src_port
        self.dst_port = dst_port


class ICMP(TransportProtocol):
    type: str

    def __init__(self, type):
        super().__init__("ICMP")

        self.type = type


class ApplicationProtocol:
    name: str

    def __init__(self, name):
        self.name = name


class PacketInfo:
    index: int
    __frame_type: str

    length: int
    real_length: int

    src_mac: hex
    dst_mac: hex

    ether_type: EtherType = None
    sap: Sap = None

    transport_protocol: TransportProtocol = None
    application_protocol: ApplicationProtocol = None

    frame: hex

    def __init__(self, index):
        self.index = index

    def get_frame_type(self):
        return self.__frame_type

    def set_ethernet(self):
        self.__frame_type = "Ethernet II"

    def set_ieee_raw(self):
        self.__frame_type = "IEEE 802.3 - Raw"

    def set_ieee_snap(self):
        self.__frame_type = "IEEE 802.3 - LLC + SNAP"

    def set_ieee_llc(self):
        self.__frame_type = "IEEE 802.3 - LLC"

    def is_ethernet(self):
        if self.__frame_type == "Ethernet II":
            return True
        else:
            return False

    def is_ieee_raw(self):
        if self.__frame_type == "IEEE 802.3 - Raw":
            return True
        else:
            return False

    def is_ieee_snap(self):
        if self.__frame_type == "IEEE 802.3 - LLC + SNAP":
            return True
        else:
            return False

    def is_ieee_llc(self):
        if self.__frame_type == "IEEE 802.3 - LLC":
            return True
        else:
            return False


def check_syn(flag):
    return flag & (1 << 1)


def check_ack(flag):
    return flag & (1 << 4)


def check_fin(flag):
    return flag & 1


def check_rst(flag):
    return flag & (1 << 2)


class TCPCommunication:
    successful: bool = False
    frames = []

    def __init__(self):
        self.successful = False
        self.frames = []


class ARPCommunication:
    hasReply: bool
    frames = []

    def __init__(self):
        self.hasReply = False
        self.frames = []


def check_communication_start(flag, syn, syn_ack, ack):
    if syn is False:
        if check_syn(flag):
            return "syn"
    elif syn_ack is False:
        if check_syn(flag) and check_ack(flag):
            return "syn_ack"
    elif ack is False:
        if check_ack(flag):
            return "ack"

    return "error"


def check_communication_end(flag, fin_ack1, ack1, fin_ack2, ack2):
    if check_rst(flag):
        return "rst"
    elif fin_ack1 is False:
        if check_fin(flag) and check_ack(flag):
            return "fin_ack1"
    elif ack1 is False:
        if check_fin(flag) and check_ack(flag):
            return "fin_ack2"
        elif check_ack(flag):
            return "ack1"
    elif fin_ack2 is False:
        if check_fin(flag) and check_ack(flag):
            return "fin_ack2"
    elif ack2 is False:
        if check_ack(flag):
            return "ack2"

    return "error"


def get_arp_communications(communication_groups):
    communications = []
    unfinished_communication = ARPCommunication()

    for key in communication_groups:
        communication_group = communication_groups[key]
        communication = ARPCommunication()

        has_request = False
        has_reply = False

        request_ip = ""
        reply_ip = ""

        for packet_info in communication_group:
            if has_request is False and packet_info.dst_mac == "ffffffffffff":
                has_request = True

                request_ip = packet_info.ether_type.src_ip
                reply_ip = packet_info.ether_type.dst_ip
            elif has_reply is False and packet_info.dst_mac != "ffffffffffff" \
                    and packet_info.ether_type.src_ip == reply_ip:
                has_reply = True

            communication.frames.append(packet_info)

            if has_request is True and has_reply is True:
                has_request = False
                has_reply = False

                request_ip = ""
                reply_ip = ""

                communications.append(communication)
                communication = ARPCommunication()


        for packet_info in communication.frames:
            unfinished_communication.frames.append(packet_info)

    communications.insert(0, unfinished_communication)

    return communications


def get_tcp_communications(communication_groups):
    communications = []

    for key in communication_groups:
        communication_group = communication_groups[key]
        communication = TCPCommunication()

        syn = False
        syn_ack = False
        ack = False

        fin_ack1 = False
        ack1 = False
        fin_ack2 = False
        ack2 = False

        for packet_info in communication_group:
            if isinstance(packet_info.transport_protocol, TCP):
                flag = packet_info.transport_protocol.flag

                # COMMUNICATION START

                # if communication has not started check for starting conditions
                if not(syn is True and syn_ack is True and ack is True):
                    check_result = check_communication_start(flag, syn, syn_ack, ack)

                    if check_result == "error":
                        syn = False
                        syn_ack = False
                        ack = False

                        communication = TCPCommunication()

                        check_result = check_communication_start(flag, syn, syn_ack, ack)

                    if check_result == "error":
                        continue
                    elif check_result == "syn":
                        syn = True
                        syn_ack = False
                        ack = False

                        communication.frames.append(packet_info)
                        continue
                    elif check_result == "syn_ack":
                        syn = True
                        syn_ack = True
                        ack = False

                        communication.frames.append(packet_info)
                        continue
                    elif check_result == "ack":
                        syn = True
                        syn_ack = True
                        ack = True

                        communication.frames.append(packet_info)
                        continue
                # if communication has started check for new communication start
                elif check_syn(flag):
                    communications.append(communication)

                    communication = TCPCommunication()
                    communication.frames.append(packet_info)

                    syn = True
                    syn_ack = False
                    ack = False

                    continue

                # communication continues
                communication.frames.append(packet_info)

                # communication end
                check_result = check_communication_end(flag, fin_ack1, ack1, fin_ack2, ack2)

                if check_result == "error":
                    fin_ack1 = False
                    ack1 = False
                    fin_ack2 = False
                    ack2 = False

                    check_result = check_communication_end(flag, fin_ack1, ack1, fin_ack2, ack2)

                if check_result == "error":
                    continue
                elif check_result == "fin_ack1":
                    fin_ack1 = True
                    ack1 = False
                    fin_ack2 = False
                    ack2 = False
                elif check_result == "ack1":
                    fin_ack1 = True
                    ack1 = True
                    fin_ack2 = False
                    ack2 = False
                elif check_result == "fin_ack2":
                    fin_ack1 = True
                    ack1 = True
                    fin_ack2 = True
                    ack2 = False
                elif check_result == "ack2" or check_result == "rst":
                    fin_ack1 = True
                    ack1 = True
                    fin_ack2 = True
                    ack2 = True

                if fin_ack1 is True and ack1 is True and fin_ack2 is True and ack2 is True:
                    communication.successful = True
                    communications.append(communication)
                    communication = TCPCommunication()

        if len(communication.frames) > 0:
            communications.append(communication)

    return communications


def output_standard(output_file_name, packets_info, dst_ip_dict):
    output_file = open("Output/" + output_file_name, "w", encoding="utf-8")

    for packet_info in packets_info:
        output_file.write("rámec " + str(packet_info.index) + "\n")

        output_file.write("dĺžka rámca poskytnutá pcap API - " + str(packet_info.length) + " B\n")
        output_file.write("dĺžka rámca poskytnutá po médiu - " + str(packet_info.real_length) + " B\n")

        output_file.write(packet_info.get_frame_type() + "\n")

        output_file.write("Zdrojová MAC adresa: " + transform_bytes(packet_info.src_mac) + "\n")
        output_file.write("Cieľová MAC adresa: " + transform_bytes(packet_info.dst_mac) + "\n")

        if packet_info.sap is not None:
            output_file.write(packet_info.sap.name + "\n")

        if packet_info.ether_type is not None:
            output_file.write(packet_info.ether_type.name + "\n")

            if isinstance(packet_info.ether_type, IPv4):
                output_file.write("zdrojová IP adresa: " + packet_info.ether_type.src_ip + "\n")
                output_file.write("cieľová IP adresa: " + packet_info.ether_type.dst_ip + "\n")

        if packet_info.transport_protocol is not None:
            output_file.write(packet_info.transport_protocol.name + "\n")

        if packet_info.application_protocol is not None:
            output_file.write(packet_info.application_protocol.name + "\n")

        if packet_info.transport_protocol is not None:
            if isinstance(packet_info.transport_protocol, TCP) or isinstance(packet_info.transport_protocol, UDP):
                output_file.write("zdrojový port: " + str(packet_info.transport_protocol.src_port) + "\n")
                output_file.write("cieľový port: " + str(packet_info.transport_protocol.dst_port) + "\n")

        packet_frame = transform_frame(packet_info.frame)
        for bytes_string in packet_frame:
            output_file.write(bytes_string + "\n")

        output_file.write("\n")

    if dst_ip_dict is not None:
        output_file.write("IP adresy vysielajúcich uzlov:\n")
        for dst_ip in dst_ip_dict:
            output_file.write(dst_ip + "\n")

        output_file.write("\n")

        output_file.write("Adresa uzla s najväčším počtom paketov:\n")
        if dst_ip_dict:
            max_dst_ip = max(dst_ip_dict, key=dst_ip_dict.get)
            output_file.write(max_dst_ip + "\n")

    output_file.close()
    print("Výstupný súbor \"" + output_file_name + "\" bol vygenerovaný.")


starting_tftp = []
started_tftp = []


def analyze_packet(packet_hex, packet_index):

    # BASIC PACKET INFO

    packet_info = PacketInfo(packet_index)

    packet_info.frame = packet_hex

    packet_info.length = int(len(packet_hex) / 2)
    packet_info.real_length = packet_info.length + 4

    if packet_info.real_length < 64:
        packet_info.real_length = 64

    # LINK LAYER ANALYSIS

    data_length_hex = get_data_length_hex(packet_hex)
    data_length = int(data_length_hex, 16)

    ether_type = None
    sap = None

    # Type of frame
    if data_length > 1500:
        packet_info.set_ethernet()

        ether_type_hex = data_length_hex
        ether_type = identify_hex(ether_type_hex, ether_types_file)

        link_layer_length = 28
    else:
        sap_hex = get_sap_hex(packet_hex)
        sap = identify_hex(sap_hex, sap_file)

        if sap == "Global DSAP":
            packet_info.set_ieee_raw()

            packet_info.sap.name = "IPX"

            link_layer_length = 34
        elif sap == "SNAP":
            packet_info.set_ieee_snap()

            ether_type_hex = data_length_hex
            ether_type = identify_hex(ether_type_hex, ether_types_file)

            link_layer_length = 44
        else:
            packet_info.set_ieee_llc()

            link_layer_length = 34

    if ether_type == "IPv4":
        packet_info.ether_type = IPv4()
    elif ether_type == "ARP":
        packet_info.ether_type = ARP()
    elif ether_type is not None:
        packet_info.ether_type = EtherType(EtherType)

    if sap is not None:
        packet_info.sap = Sap(sap)

    # MAC addresses
    packet_info.src_mac = get_src_mac(packet_hex)
    packet_info.dst_mac = get_dst_mac(packet_hex)

    # NETWORK LAYER ANALYSIS

    remaining_packet_hex = packet_hex[link_layer_length:]

    transport_protocol = None
    network_layer_length = 0

    # Ether type
    if packet_info.ether_type is not None:
        if isinstance(packet_info.ether_type, IPv4):
            src_ip_hex = ipv4_get_src_ip_hex(remaining_packet_hex)
            dst_ip_hex = ipv4_get_dst_ip_hex(remaining_packet_hex)

            packet_info.ether_type.src_ip = hex_to_ip(src_ip_hex)
            packet_info.ether_type.dst_ip = hex_to_ip(dst_ip_hex)

            transport_protocol_hex = ipv4_get_protocol(remaining_packet_hex)
            transport_protocol = identify_hex(transport_protocol_hex, ip_protocols_file)

            network_layer_length = 40
        elif isinstance(packet_info.ether_type, ARP):
            src_ip_hex = arp_get_src_ip_hex(remaining_packet_hex)
            dst_ip_hex = arp_get_dst_ip_hex(remaining_packet_hex)

            packet_info.ether_type.src_ip = hex_to_ip(src_ip_hex)
            packet_info.ether_type.dst_ip = hex_to_ip(dst_ip_hex)

            network_layer_length = 56

    # TRANSPORT LAYER ANALYSIS

    remaining_packet_hex = remaining_packet_hex[network_layer_length:]

    if transport_protocol is not None:
        if transport_protocol == "TCP":
            src_port_hex = tcp_get_src_port_hex(remaining_packet_hex)
            src_port_int = int(src_port_hex, 16)
            src_port = identify_hex(src_port_hex, tcp_file)

            dst_port_hex = tcp_get_dst_port_hex(remaining_packet_hex)
            dst_port_int = int(dst_port_hex, 16)
            dst_port = identify_hex(dst_port_hex, tcp_file)

            flag_hex = tcp_get_flag_hex(remaining_packet_hex)
            flag_int = int(flag_hex, 16)

            packet_info.transport_protocol = TCP(src_port_int, dst_port_int, packet_info.ether_type.src_ip,
                                                 packet_info.ether_type.dst_ip, flag_int)

            if src_port is not None:
                packet_info.application_protocol = ApplicationProtocol(src_port)
            elif dst_port is not None:
                packet_info.application_protocol = ApplicationProtocol(dst_port)
        elif transport_protocol == "UDP":
            src_port_hex = tcp_get_src_port_hex(remaining_packet_hex)
            src_port_int = int(src_port_hex, 16)
            src_port = identify_hex(src_port_hex, udp_file)

            dst_port_hex = tcp_get_dst_port_hex(remaining_packet_hex)
            dst_port_int = int(dst_port_hex, 16)
            dst_port = identify_hex(dst_port_hex, udp_file)

            packet_info.transport_protocol = UDP(src_port_int, dst_port_int)

            if src_port is not None:
                packet_info.application_protocol = ApplicationProtocol(src_port)
            elif dst_port is not None:
                packet_info.application_protocol = ApplicationProtocol(dst_port)

                # tftp analysis
                if packet_info.application_protocol.name == "tftp":
                    starting_tftp.append(src_port)
            elif dst_port in starting_tftp:
                starting_tftp.remove(dst_port)
                started_tftp.append((src_port, dst_port))

                packet_info.application_protocol = ApplicationProtocol("tftp")
            elif (src_port, dst_port) in started_tftp or (dst_port, src_port) in started_tftp:
                packet_info.application_protocol = ApplicationProtocol("tftp")
        elif transport_protocol == "ICMP":
            type_hex = icmp_get_type_hex(remaining_packet_hex)
            type_str = identify_hex(type_hex, icmp_file)

            packet_info.transport_protocol = ICMP(type_str)
        else:
            packet_info.transport_protocol = TransportProtocol(transport_protocol)

    return packet_info


def generate_dst_ip_dictionary(packets_info):
    dst_ip_dict = {}

    for packet_info in packets_info:
        if packet_info.ether_type is not None:
            if isinstance(packet_info.ether_type, IPv4):
                dst_ip = packet_info.ether_type.dst_ip

                if dst_ip in dst_ip_dict:
                    dst_ip_dict[dst_ip] += 1
                else:
                    dst_ip_dict[dst_ip] = 1

    return dst_ip_dict


def filter_packets_info_by_application_protocol(application_protocol, packets_info):
    filtered_packets_info = []

    for packet_info in packets_info:
        if packet_info.application_protocol is not None:
            if packet_info.application_protocol.name == application_protocol:
                filtered_packets_info.append(packet_info)

    return filtered_packets_info


def filter_packets_info_by_transport_protocol(transport_protocol, packets_info):
    filtered_packets_info = []

    for packet_info in packets_info:
        if packet_info.transport_protocol is not None:
            if packet_info.transport_protocol.name == transport_protocol:
                filtered_packets_info.append(packet_info)

    return filtered_packets_info


def filter_packets_info_by_ether_type(ether_type, packets_info):
    filtered_packets_info = []

    for packet_info in packets_info:
        if packet_info.ether_type is not None:
            if packet_info.ether_type.name == ether_type:
                filtered_packets_info.append(packet_info)

    return filtered_packets_info


def group_communications(packets_info):
    communication_groups = {}

    for packet_info in packets_info:
        if isinstance(packet_info.transport_protocol, TCP):
            src_socket = packet_info.transport_protocol.src_socket
            dst_socket = packet_info.transport_protocol.dst_socket

            if (src_socket, dst_socket) in communication_groups:
                communication_groups[(src_socket, dst_socket)].append(packet_info)
            elif (dst_socket, src_socket) in communication_groups:
                communication_groups[(dst_socket, src_socket)].append(packet_info)
            else:
                communication_groups[(src_socket, dst_socket)] = [packet_info]
        elif isinstance(packet_info.ether_type, ARP):
            src_ip = packet_info.ether_type.src_ip
            dst_ip = packet_info.ether_type.dst_ip

            if (src_ip, dst_ip) in communication_groups:
                communication_groups[(src_ip, dst_ip)].append(packet_info)
            elif (dst_ip, src_ip) in communication_groups:
                communication_groups[(dst_ip, src_ip)].append(packet_info)
            else:
                communication_groups[(src_ip, dst_ip)] = [packet_info]

    return communication_groups


def output_tcp_frame(output_file, packet_info):
    output_file.write("rámec " + str(packet_info.index) + "\n")

    output_file.write("dĺžka rámca poskytnutá pcap API - " + str(packet_info.length) + " B\n")
    output_file.write("dĺžka rámca poskytnutá po médiu - " + str(packet_info.real_length) + " B\n")

    output_file.write(packet_info.get_frame_type() + "\n")

    output_file.write("Zdrojová MAC adresa: " + transform_bytes(packet_info.src_mac) + "\n")
    output_file.write("Cieľová MAC adresa: " + transform_bytes(packet_info.dst_mac) + "\n")

    if packet_info.sap is not None:
        output_file.write(packet_info.sap.name + "\n")

    if packet_info.ether_type is not None:
        output_file.write(packet_info.ether_type.name + "\n")

        if isinstance(packet_info.ether_type, IPv4):
            output_file.write("zdrojová IP adresa: " + packet_info.ether_type.src_ip + "\n")
            output_file.write("cieľová IP adresa: " + packet_info.ether_type.dst_ip + "\n")

    if packet_info.transport_protocol is not None:
        output_file.write(packet_info.transport_protocol.name + "\n")

    if packet_info.application_protocol is not None:
        output_file.write(packet_info.application_protocol.name + "\n")

    if packet_info.transport_protocol is not None:
        if isinstance(packet_info.transport_protocol, TCP) or isinstance(packet_info.transport_protocol, UDP):
            output_file.write("zdrojový port: " + str(packet_info.transport_protocol.src_port) + "\n")
            output_file.write("cieľový port: " + str(packet_info.transport_protocol.dst_port) + "\n")

    packet_frame = transform_frame(packet_info.frame)
    for bytes_string in packet_frame:
        output_file.write(bytes_string + "\n")

    output_file.write("\n")


def output_arp_frame(output_file, packet_info):
    if packet_info.dst_mac == "ffffffffffff":
        output_file.write("ARP-Request, IP adresa: " + packet_info.ether_type.dst_ip + " MAC adresa: ???\n")
    else:
        output_file.write(
            "ARP-Reply, IP adresa: " + packet_info.ether_type.src_ip + " MAC adresa: " + packet_info.src_mac + "\n")

    output_file.write("rámec " + str(packet_info.index) + "\n")

    output_file.write("dĺžka rámca poskytnutá pcap API - " + str(packet_info.length) + " B\n")
    output_file.write("dĺžka rámca poskytnutá po médiu - " + str(packet_info.real_length) + " B\n")

    output_file.write(packet_info.get_frame_type() + "\n")

    if packet_info.sap is not None:
        output_file.write(packet_info.sap.name + "\n")

    if packet_info.ether_type is not None:
        output_file.write(packet_info.ether_type.name + "\n")

    output_file.write("Zdrojová MAC adresa: " + transform_bytes(packet_info.src_mac) + "\n")
    output_file.write("Cieľová MAC adresa: " + transform_bytes(packet_info.dst_mac) + "\n")

    packet_frame = transform_frame(packet_info.frame)
    for bytes_string in packet_frame:
        output_file.write(bytes_string + "\n")

    output_file.write("\n")


def output_tcp_communications(output_file_name, tcp_communications):
    output_file = open("Output/" + output_file_name, "w", encoding="utf-8")

    communication_index = 1

    found_success = False
    found_fail = False

    for tcp_communication in tcp_communications:
        if found_success is False and tcp_communication.successful:
            output_file.write("Komunikácia č. " + str(communication_index) + " - úplná\n")
            output_file.write("\n")

            found_success = True
        elif found_fail is False and not tcp_communication.successful:
            output_file.write("Komunikácia č. " + str(communication_index) + " - neúplná\n")
            output_file.write("\n")

            found_fail = True
        else:
            continue

        if len(tcp_communication.frames) < 20:
            output_file.write("Komunikácia je vypísaná celá (spolu "
                              + str(len(tcp_communication.frames)) + " rámcov)\n")
            output_file.write("\n")

            for packet_info in tcp_communication.frames:
                output_tcp_frame(output_file, packet_info)
        else:
            output_file.write("Komunikácia nie je vypísaná celá (spolu "
                              + str(len(tcp_communication.frames)) + " rámcov)\n")
            output_file.write("\n")

            output_file.write("Prvých 10 rámcov:\n")
            output_file.write("\n")

            for packet_info in tcp_communication.frames[:10]:
                output_tcp_frame(output_file, packet_info)

            output_file.write("Posledných 10 rámcov:\n")
            output_file.write("\n")

            for packet_info in tcp_communication.frames[-10:]:
                output_tcp_frame(output_file, packet_info)

        if found_success is True and found_fail is True:
            break

        communication_index += 1

    if found_success is False:
        output_file.write("Úplná komunikácia nebol nájdená.\n")

    if found_fail is False:
        output_file.write("Neúplná komunikácia nebol nájdená.\n")

    output_file.close()
    print("Výstupný súbor \"" + output_file_name + "\" bol vygenerovaný.")


def output_arp_communications(arp_communications):
    output_file_name = "Výstup4i.txt"
    output_file = open("Output/" + output_file_name, "w", encoding="utf-8")

    for communication_index in range(1, len(arp_communications)):
        arp_communication = arp_communications[communication_index]

        output_file.write("Komunikácia č. " + str(communication_index) + "\n")
        output_file.write("\n")

        for packet_info in arp_communication.frames:
            output_arp_frame(output_file, packet_info)

    if len(arp_communications[0].frames) > 0:
        output_file.write("Komunikácie bez odpovede:\n")
        output_file.write("\n")

        remaining_communication = arp_communications[0]

        for packet_info in remaining_communication.frames:
            output_arp_frame(output_file, packet_info)

    output_file.close()
    print("Výstupný súbor \"" + output_file_name + "\" bol vygenerovaný.")


def output_icmp_communications(filtered_packets):
    output_file_name = "Výstup4h.txt"
    output_file = open("Output/" + output_file_name, "w", encoding="utf-8")

    for packet_info in filtered_packets:
        output_file.write("rámec " + str(packet_info.index) + "\n")

        output_file.write("dĺžka rámca poskytnutá pcap API - " + str(packet_info.length) + " B\n")
        output_file.write("dĺžka rámca poskytnutá po médiu - " + str(packet_info.real_length) + " B\n")

        output_file.write(packet_info.get_frame_type() + "\n")

        output_file.write("Zdrojová MAC adresa: " + transform_bytes(packet_info.src_mac) + "\n")
        output_file.write("Cieľová MAC adresa: " + transform_bytes(packet_info.dst_mac) + "\n")

        if packet_info.sap is not None:
            output_file.write(packet_info.sap.name + "\n")

        if packet_info.ether_type is not None:
            output_file.write(packet_info.ether_type.name + "\n")

            if isinstance(packet_info.ether_type, IPv4):
                output_file.write("zdrojová IP adresa: " + packet_info.ether_type.src_ip + "\n")
                output_file.write("cieľová IP adresa: " + packet_info.ether_type.dst_ip + "\n")

        if packet_info.transport_protocol is not None:
            output_file.write(packet_info.transport_protocol.name + "\n")

            if isinstance(packet_info.transport_protocol, ICMP):
                if packet_info.transport_protocol.type is not None:
                    output_file.write(packet_info.transport_protocol.type + "\n")
                else:
                    output_file.write("undefined type\n")

        packet_frame = transform_frame(packet_info.frame)
        for bytes_string in packet_frame:
            output_file.write(bytes_string + "\n")

        output_file.write("\n")

    output_file.close()
    print("Výstupný súbor \"" + output_file_name + "\" bol vygenerovaný.")


def output_tftp_communications(filtered_packets):
    output_file_name = "Výstup4g.txt"
    output_file = open("Output/" + output_file_name, "w", encoding="utf-8")

    for packet_info in filtered_packets:
        output_file.write("rámec " + str(packet_info.index) + "\n")

        output_file.write("dĺžka rámca poskytnutá pcap API - " + str(packet_info.length) + " B\n")
        output_file.write("dĺžka rámca poskytnutá po médiu - " + str(packet_info.real_length) + " B\n")

        output_file.write(packet_info.get_frame_type() + "\n")

        output_file.write("Zdrojová MAC adresa: " + transform_bytes(packet_info.src_mac) + "\n")
        output_file.write("Cieľová MAC adresa: " + transform_bytes(packet_info.dst_mac) + "\n")

        if packet_info.sap is not None:
            output_file.write(packet_info.sap.name + "\n")

        if packet_info.ether_type is not None:
            output_file.write(packet_info.ether_type.name + "\n")

            if isinstance(packet_info.ether_type, IPv4):
                output_file.write("zdrojová IP adresa: " + packet_info.ether_type.src_ip + "\n")
                output_file.write("cieľová IP adresa: " + packet_info.ether_type.dst_ip + "\n")

        if packet_info.transport_protocol is not None:
            output_file.write(packet_info.transport_protocol.name + "\n")

        if packet_info.application_protocol is not None:
            output_file.write(packet_info.application_protocol.name + "\n")

        if packet_info.transport_protocol is not None:
            if isinstance(packet_info.transport_protocol, TCP) or isinstance(packet_info.transport_protocol, UDP):
                output_file.write("zdrojový port: " + str(packet_info.transport_protocol.src_port) + "\n")
                output_file.write("cieľový port: " + str(packet_info.transport_protocol.dst_port) + "\n")

        packet_frame = transform_frame(packet_info.frame)
        for bytes_string in packet_frame:
            output_file.write(bytes_string + "\n")

        output_file.write("\n")

    output_file.close()
    print("Výstupný súbor \"" + output_file_name + "\" bol vygenerovaný.")


def analyze_tcp_communications(output_file_name, application_protocol, packets_info):
    filtered_packets = filter_packets_info_by_application_protocol(application_protocol, packets_info)
    communication_groups = group_communications(filtered_packets)

    tcp_communications = get_tcp_communications(communication_groups)

    output_tcp_communications(output_file_name, tcp_communications)


def analyze_arp_communications(packets_info):
    filtered_packets = filter_packets_info_by_ether_type("ARP", packets_info)
    communication_groups = group_communications(filtered_packets)
    arp_communications = get_arp_communications(communication_groups)

    output_arp_communications(arp_communications)


def analyze_icmp_communications(packets_info):
    filtered_packets = filter_packets_info_by_transport_protocol("ICMP", packets_info)

    output_icmp_communications(filtered_packets)


def analyze_tftp_communications(packets_info):
    filtered_packets = filter_packets_info_by_application_protocol("tftp", packets_info)

    output_tftp_communications(filtered_packets)


def analyze_packets(packets):
    packets_info = []
    packet_index = 0

    for packet in packets:
        packet_index += 1
        packet_bytes = raw(packet)
        packet_hex = packet_bytes.hex()

        packet_info = analyze_packet(packet_hex, packet_index)
        packets_info.append(packet_info)

    starting_tftp = []
    started_tftp = []

    return packets_info


def output_pim_communications(filtered_packets):
    output_file_name = "Doimplementácia.txt"
    output_file = open("Output/" + output_file_name, "w", encoding="utf-8")

    output_file.write("počet rámcov PIM - " + str(len(filtered_packets)) + "\n")
    output_file.write("\n")

    for packet_info in filtered_packets:
        output_file.write("rámec " + str(packet_info.index) + "\n")

        output_file.write("dĺžka rámca poskytnutá pcap API - " + str(packet_info.length) + " B\n")
        output_file.write("dĺžka rámca poskytnutá po médiu - " + str(packet_info.real_length) + " B\n")

        output_file.write(packet_info.get_frame_type() + "\n")

        output_file.write("Zdrojová MAC adresa: " + transform_bytes(packet_info.src_mac) + "\n")
        output_file.write("Cieľová MAC adresa: " + transform_bytes(packet_info.dst_mac) + "\n")

        if packet_info.sap is not None:
            output_file.write(packet_info.sap.name + "\n")

        if packet_info.ether_type is not None:
            output_file.write(packet_info.ether_type.name + "\n")

            if isinstance(packet_info.ether_type, IPv4):
                output_file.write("zdrojová IP adresa: " + packet_info.ether_type.src_ip + "\n")
                output_file.write("cieľová IP adresa: " + packet_info.ether_type.dst_ip + "\n")

        if packet_info.transport_protocol is not None:
            output_file.write(packet_info.transport_protocol.name + "\n")

        if packet_info.application_protocol is not None:
            output_file.write(packet_info.application_protocol.name + "\n")

        if packet_info.transport_protocol is not None:
            if isinstance(packet_info.transport_protocol, TCP) or isinstance(packet_info.transport_protocol, UDP):
                output_file.write("zdrojový port: " + str(packet_info.transport_protocol.src_port) + "\n")
                output_file.write("cieľový port: " + str(packet_info.transport_protocol.dst_port) + "\n")

        packet_frame = transform_frame(packet_info.frame)
        for bytes_string in packet_frame:
            output_file.write(bytes_string + "\n")

        output_file.write("\n")

    output_file.close()
    print("Výstupný súbor \"" + output_file_name + "\" bol vygenerovaný.")


def analyze_pim_communications(packets_info):
    filtered_packets = filter_packets_info_by_transport_protocol("PIM", packets_info)

    output_pim_communications(filtered_packets)


while True:
    input_file_name = input("Názov čítaného súboru (s príponou): ")

    try:
        my_packets = rdpcap("Input/" + input_file_name)
        break
    except IOError:
        print("Zadaný súbor neexistuje.")
        continue

packetsInfo = analyze_packets(my_packets)

desired_output = input("Kód výstupného súboru (pre info si prečítajte README.txt): ")
if desired_output == "0":
    dst_ip_dictionary = generate_dst_ip_dictionary(packetsInfo)
    output_standard("Výstup1-3.txt", packetsInfo, dst_ip_dictionary)
elif desired_output == "1":
    analyze_tcp_communications("Výstup4a.txt", "http", packetsInfo)
elif desired_output == "2":
    analyze_tcp_communications("Výstup4b.txt", "https", packetsInfo)
elif desired_output == "3":
    analyze_tcp_communications("Výstup4c.txt", "telnet", packetsInfo)
elif desired_output == "4":
    analyze_tcp_communications("Výstup4d.txt", "ssh", packetsInfo)
elif desired_output == "5":
    analyze_tcp_communications("Výstup4e.txt", "ftp-control", packetsInfo)
elif desired_output == "6":
    analyze_tcp_communications("Výstup4f.txt", "ftp-data", packetsInfo)
elif desired_output == "7":
    analyze_tftp_communications(packetsInfo)
elif desired_output == "8":
    analyze_icmp_communications(packetsInfo)
elif desired_output == "9":
    analyze_arp_communications(packetsInfo)
elif desired_output == "10":
    analyze_pim_communications(packetsInfo)

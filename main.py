from scapy.compat import raw
from scapy.utils import rdpcap


sap_file = "SAP.txt"
ip_protocols_file = "IP_Protocols.txt"
tcp_file = "TCP_Ports.txt"
udp_file = "UDP_Ports.txt"
ether_types_file = "EtherTypes.txt"


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
    new_string_list = []
    new_string = ""
    i = 0

    for char in old_string:
        if i % 32 == 0 and i != 0:
            new_string_list.append(transform_bytes(new_string))
            new_string = ""

        new_string += char
        i += 1

    if new_string != "":
        new_string_list.append(transform_bytes(new_string))

    return new_string_list


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


def get_src_ip_hex(packet_hex):
    return packet_hex[24:32]


def get_dst_ip_hex(packet_hex):
    return packet_hex[32:40]


def ipv4_get_src_ip(packet_hex):
    src_ip_hex = get_src_ip_hex(packet_hex)

    src_ip_hex1 = src_ip_hex[0:2]
    src_ip_hex2 = src_ip_hex[2:4]
    src_ip_hex3 = src_ip_hex[4:6]
    src_ip_hex4 = src_ip_hex[6:8]

    src_ip_dec1 = hex_to_dec(src_ip_hex1)
    src_ip_dec2 = hex_to_dec(src_ip_hex2)
    src_ip_dec3 = hex_to_dec(src_ip_hex3)
    src_ip_dec4 = hex_to_dec(src_ip_hex4)

    src_ip = str(src_ip_dec1) + "." + str(src_ip_dec2) + "." + str(src_ip_dec3) + "." + str(src_ip_dec4)

    return src_ip


def ipv4_get_dst_ip(packet_hex):
    dst_ip_hex = get_dst_ip_hex(packet_hex)

    dst_ip_hex1 = dst_ip_hex[0:2]
    dst_ip_hex2 = dst_ip_hex[2:4]
    dst_ip_hex3 = dst_ip_hex[4:6]
    dst_ip_hex4 = dst_ip_hex[6:8]

    dst_ip_dec1 = hex_to_dec(dst_ip_hex1)
    dst_ip_dec2 = hex_to_dec(dst_ip_hex2)
    dst_ip_dec3 = hex_to_dec(dst_ip_hex3)
    dst_ip_dec4 = hex_to_dec(dst_ip_hex4)

    dst_ip = str(dst_ip_dec1) + "." + str(dst_ip_dec2) + "." + str(dst_ip_dec3) + "." + str(dst_ip_dec4)

    return dst_ip


def ipv4_get_protocol(packet_hex):
    return packet_hex[18:20]


def tcp_get_src_port_hex(packet_hex):
    return packet_hex[0:4]


def tcp_get_dst_port_hex(packet_hex):
    return packet_hex[4:8]


def udp_get_src_port_hex(packet_hex):
    return packet_hex[0:4]


def udp_get_dst_port_hex(packet_hex):
    return packet_hex[4:8]


class Sap:
    name: str

    def __init__(self, name):
        self.name = name


class EtherType:
    name: str

    def __init__(self, name):
        self.name = name


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

    def __init__(self, src_port, dst_port):
        super().__init__("TCP")
        self.src_port = src_port
        self.dst_port = dst_port


class UDP(TransportProtocol):
    src_port: int
    dst_port: int

    def __init__(self, src_port, dst_port):
        super().__init__("UDP")
        self.src_port = src_port
        self.dst_port = dst_port


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


def output_standard(output_file, packets_info, dst_ip_dictionary):
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

        packet_frame = transform_frame(packet_info.frame)
        for bytes_string in packet_frame:
            output_file.write(bytes_string + "\n")

        output_file.write("\n")

    output_file.write("IP adresy vysielajúcich uzlov:\n")
    for dst_ip in dst_ip_dictionary:
        output_file.write(dst_ip + "\n")

    output_file.write("\n")

    output_file.write("Adresa uzla s najväčším počtom paketov:\n")
    if dst_ip_dictionary:
        max_dst_ip = max(dst_ip_dictionary, key=dst_ip_dictionary.get)
        output_file.write(max_dst_ip + "\n")


def analyze_packet(packet_hex, packet_index):
    packet_info = PacketInfo(packet_index)

    # BASIC PACKET INFO

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
        elif packet_info.sap.name == "SNAP":
            packet_info.set_ieee_snap()

            ether_type_hex = data_length_hex
            ether_type = identify_hex(ether_type_hex, ether_types_file)

            link_layer_length = 44
        else:
            packet_info.set_ieee_llc()

            link_layer_length = 34

    if ether_type == "IPv4":
        packet_info.ether_type = IPv4()
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
            packet_info.ether_type.src_ip = ipv4_get_src_ip(remaining_packet_hex)
            packet_info.ether_type.dst_ip = ipv4_get_dst_ip(remaining_packet_hex)

            transport_protocol_hex = ipv4_get_protocol(remaining_packet_hex)
            transport_protocol = identify_hex(transport_protocol_hex, ip_protocols_file)

            network_layer_length = 40

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

            packet_info.transport_protocol = TCP(src_port_int, dst_port_int)

            if src_port is not None:
                packet_info.application_protocol = ApplicationProtocol(src_port)

            if dst_port is not None:
                packet_info.application_protocol = ApplicationProtocol(dst_port)
        elif transport_protocol == "UDP":
            src_port_hex = tcp_get_src_port_hex(remaining_packet_hex)
            src_port_int = int(src_port_hex, 16)
            src_port = identify_hex(src_port_hex, tcp_file)

            dst_port_hex = tcp_get_dst_port_hex(remaining_packet_hex)
            dst_port_int = int(dst_port_hex, 16)
            dst_port = identify_hex(dst_port_hex, tcp_file)

            packet_info.transport_protocol = UDP(src_port_int, dst_port_int)

            if src_port is not None:
                packet_info.application_protocol = ApplicationProtocol(src_port)

            if dst_port is not None:
                packet_info.application_protocol = ApplicationProtocol(dst_port)

    packet_info.frame = packet_hex

    return packet_info


def generate_dst_ip_dictionary(packets_info):
    dst_ip_dictionary = {}

    for packet_info in packets_info:
        if packet_info.ether_type is not None:
            if isinstance(packet_info.ether_type, IPv4):
                dst_ip = packet_info.ether_type.dst_ip

                if dst_ip in dst_ip_dictionary:
                    dst_ip_dictionary[dst_ip] += 1
                else:
                    dst_ip_dictionary[dst_ip] = 1

    return dst_ip_dictionary


def analyze_packets(packets):
    packets_info = []
    packet_index = 0

    for packet in packets:
        packet_index += 1
        packet_bytes = raw(packet)
        packet_hex = packet_bytes.hex()

        packet_info = analyze_packet(packet_hex, packet_index)
        packets_info.append(packet_info)

    dst_ip_dictionary = generate_dst_ip_dictionary(packets_info)

    output_file = open("Výstup1-3.txt", "w", encoding="utf-8")
    output_standard(output_file, packets_info, dst_ip_dictionary)
    output_file.close()

    print("Výstupný súbor bol vygenerovaný.")


while True:
    file_name = input("Názov čítaného súboru (s príponou): ")

    try:
        my_packets = rdpcap("PCAP/" + file_name)
    except IOError:
        print("Zadaný súbor neexistuje.")
        continue

    analyze_packets(my_packets)

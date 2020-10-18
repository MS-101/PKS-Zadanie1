from scapy.compat import raw
from scapy.utils import rdpcap


sap_file = "SAP.txt"
ip_protocols_file = "IP_Protocols.txt"
tcp_file = "TCP_Ports.txt"
udp_file = "UDP_Ports.txt"
ether_types_file = "EtherTypes.txt"


def print_bytes(output_file, packet_hex, start_index, end_index):
    for byte_index in range(start_index, end_index):
        output_file.write(packet_hex[byte_index * 2] + packet_hex[byte_index * 2 + 1] + " ")
    output_file.write("\n")


def print_frame(output_file, packet_hex):
    hex_index = 0

    for my_hex in packet_hex:
        output_file.write(my_hex)
        hex_index += 1
        if hex_index % 32 == 0:
            output_file.write("\n")
        elif hex_index % 2 == 0:
            output_file.write(" ")
    output_file.write("\n")


def hex_to_dec(hex_string):
    return int(hex_string, 16)


def print_dst_mac(output_file, packet_hex):
    print_bytes(output_file, packet_hex, 0, 6)


def print_src_mac(output_file, packet_hex):
    print_bytes(output_file, packet_hex, 6, 12)


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


def analyze_packets(output_file, packets):
    packet_index = 0
    dst_ip_dictionary = {}

    for packet in packets:
        packet_index += 1
        packet_bytes = raw(packet)
        packet_hex = packet_bytes.hex()

        # BASIC PACKET INFO

        output_file.write("rámec " + str(packet_index) + "\n")

        packet_length = int(len(packet_hex) / 2)
        real_packet_length = packet_length + 4
        if real_packet_length < 64:
            real_packet_length = 64

        output_file.write("dĺžka rámca poskytnutá pcap API - " + str(packet_length) + " B\n")
        output_file.write("dĺžka rámca prenášaného po médiu - " + str(real_packet_length) + " B\n")

        # LINK LAYER ANALYSIS

        ether_type = None
        sap = None

        data_length_hex = get_data_length_hex(packet_hex)
        data_length = int(data_length_hex, 16)

        # Type of frame
        if data_length > 1500:
            output_file.write("Ethernet II\n")

            ether_type_hex = data_length_hex
            ether_type = identify_hex(ether_type_hex, ether_types_file)

            has_ether_type = True
            has_sap = False

            link_layer_length = 28
        else:
            sap_hex = get_sap_hex(packet_hex)
            sap = identify_hex(sap_hex, sap_file)

            if sap == "Global DSAP":
                output_file.write("IEEE 802.3 - Raw\n")

                sap = "IPX"

                has_ether_type = False
                has_sap = True

                link_layer_length = 34
            elif sap == "SNAP":
                output_file.write("IEEE 802.3 - LLC + Snap\n")

                ether_type_hex = data_length_hex
                ether_type = identify_hex(ether_type_hex, ether_types_file)

                has_ether_type = True
                has_sap = True

                link_layer_length = 44
            else:
                output_file.write("IEEE 802.3 - LLC\n")

                has_ether_type = False
                has_sap = True

                link_layer_length = 34

        # MAC addresses
        output_file.write("Zdrojová MAC adresa: ")
        print_src_mac(output_file, packet_hex)
        output_file.write("Cieľová MAC adresa: ")
        print_dst_mac(output_file, packet_hex)

        # SAP
        if has_sap:
            if sap is not None:
                output_file.write(sap + "\n")
            else:
                output_file.write("undefined SAP\n")

        # NETWORK LAYER ANALYSIS

        remaining_packet_hex = packet_hex[link_layer_length:]

        transport_protocol = None
        network_layer_length = 0

        # Ether type
        if has_ether_type:
            if ether_type is not None:
                output_file.write(ether_type + "\n")

                if ether_type == "IPv4":
                    src_ip = ipv4_get_src_ip(remaining_packet_hex)
                    dst_ip = ipv4_get_dst_ip(remaining_packet_hex)

                    output_file.write("Zdrojová IP adresa: " + src_ip + "\n")
                    output_file.write("Cieľová IP adresa: " + dst_ip + "\n")

                    transport_protocol_hex = ipv4_get_protocol(remaining_packet_hex)
                    transport_protocol = identify_hex(transport_protocol_hex, ip_protocols_file)

                    if transport_protocol is not None:
                        output_file.write(transport_protocol + "\n")
                    else:
                        output_file.write("undefined transport protocol\n")

                    network_layer_length = 40

                    if transport_protocol == "TCP":
                        if dst_ip in dst_ip_dictionary:
                            dst_ip_dictionary[dst_ip] += 1
                        else:
                            dst_ip_dictionary[dst_ip] = 1
            else:
                output_file.write("undefined ether type\n")

        # TRANSPORT LAYER ANALYSIS

        remaining_packet_hex = remaining_packet_hex[network_layer_length:]

        if transport_protocol is not None:
            if transport_protocol == "TCP":
                src_port_hex = tcp_get_src_port_hex(remaining_packet_hex)
                src_port = identify_hex(src_port_hex, tcp_file)

                dst_port_hex = tcp_get_dst_port_hex(remaining_packet_hex)
                dst_port = identify_hex(dst_port_hex, tcp_file)

                if src_port is not None:
                    output_file.write(src_port + "\n")

                if dst_port is not None:
                    output_file.write(dst_port + "\n")
            elif transport_protocol == "UDP":
                src_port_hex = udp_get_src_port_hex(remaining_packet_hex)
                src_port = identify_hex(src_port_hex, udp_file)

                dst_port_hex = udp_get_dst_port_hex(remaining_packet_hex)
                dst_port = identify_hex(dst_port_hex, udp_file)

                if src_port is not None:
                    output_file.write(src_port + "\n")

                if dst_port is not None:
                    output_file.write(dst_port + "\n")

        print_frame(output_file, packet_hex)
        output_file.write("\n")

    # ALL IP ADDRESSES

    output_file.write("IP adresy vysielajúcich uzlov:\n")
    for dst_ip in dst_ip_dictionary:
        output_file.write(dst_ip + "\n")
    output_file.write("\n")

    max_dst_ip = max(dst_ip_dictionary, key=dst_ip_dictionary.get)

    output_file.write("Adresa uzla s najväčším počtom paketov:\n")
    output_file.write(max_dst_ip + "\n")
    output_file.write("\n")

    print("Výstupný súbor bol vygenerovaný.")


while True:
    file_name = input("Názov čítaného súboru (s príponou): ")

    try:
        my_packets = rdpcap("PCAP/" + file_name)
    except IOError:
        print("Zadaný súbor neexistuje.")
        continue

    outputFile = open("Výstup.txt", "w", encoding="utf-8")
    analyze_packets(outputFile, my_packets)
    outputFile.close()

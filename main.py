from scapy.compat import raw
from scapy.utils import rdpcap


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


def print_dst_mac(output_file, packet_hex):
    print_bytes(output_file, packet_hex, 0, 6)


def print_src_mac(output_file, packet_hex):
    print_bytes(output_file, packet_hex, 6, 12)


def print_src_ip(output_file, packet_hex):
    src_ip_hex = get_src_ip_hex(packet_hex)

    src_ip_hex1 = src_ip_hex[0:2]
    src_ip_hex2 = src_ip_hex[2:4]
    src_ip_hex3 = src_ip_hex[4:6]
    src_ip_hex4 = src_ip_hex[6:8]

    src_ip_dec1 = hex_to_dec(src_ip_hex1)
    src_ip_dec2 = hex_to_dec(src_ip_hex2)
    src_ip_dec3 = hex_to_dec(src_ip_hex3)
    src_ip_dec4 = hex_to_dec(src_ip_hex4)

    output_file.write(str(src_ip_dec1) + "." + str(src_ip_dec2) + "." + str(src_ip_dec3) + "." + str(src_ip_dec4))
    output_file.write("\n")


def print_dst_ip(output_file, packet_hex):
    dst_ip_hex = get_dst_ip_hex(packet_hex)

    dst_ip_hex1 = dst_ip_hex[0:2]
    dst_ip_hex2 = dst_ip_hex[2:4]
    dst_ip_hex3 = dst_ip_hex[4:6]
    dst_ip_hex4 = dst_ip_hex[6:8]

    dst_ip_dec1 = hex_to_dec(dst_ip_hex1)
    dst_ip_dec2 = hex_to_dec(dst_ip_hex2)
    dst_ip_dec3 = hex_to_dec(dst_ip_hex3)
    dst_ip_dec4 = hex_to_dec(dst_ip_hex4)

    output_file.write(str(dst_ip_dec1) + "." + str(dst_ip_dec2) + "." + str(dst_ip_dec3) + "." + str(dst_ip_dec4))
    output_file.write("\n")


def get_ether_type_hex(packet_hex):
    return packet_hex[24:28]


def get_sap_hex(packet_hex):
    return packet_hex[28:30]


def get_src_ip_hex(packet_hex):
    return packet_hex[52:60]


def get_dst_ip_hex(packet_hex):
    return packet_hex[60:68]


def get_transport_protocol(packet_hex):
    return packet_hex[46:48]


def hex_to_dec(hex_string):
    return int(hex_string, 16)


def identify_ether_type(ether_type_hex):
    ether_types_file = open("EtherTypes.txt", "r")

    ether_type = None
    for line in ether_types_file:
        words = line.split()
        if words[0] == ether_type_hex:
            ether_type = words[1]

    ether_types_file.close()

    return ether_type


def identify_sap(sap_hex):
    sap_file = open("SAP.txt", "r")

    sap = None
    for line in sap_file:
        words = line.split()
        if words[0] == sap_hex:
            sap = words[1]

    sap_file.close()

    return sap


def analyze_packet(output_file, packet, packet_index):
    packet_bytes = raw(packet)
    packet_hex = packet_bytes.hex()

    output_file.write("rámec " + str(packet_index) + "\n")

    packet_length = int(len(packet_hex) / 2)
    real_packet_length = packet_length + 4
    if real_packet_length < 64:
        real_packet_length = 64

    output_file.write("dĺžka rámca poskytnutá pcap API - " + str(packet_length) + " B\n")
    output_file.write("dĺžka rámca prenášaného po médiu - " + str(real_packet_length) + " B\n")

    ether_type_hex = get_ether_type_hex(packet_hex)
    ether_type = identify_ether_type(ether_type_hex)

    sap_hex = get_sap_hex(packet_hex)
    sap = identify_sap(sap_hex)

    if ether_type_hex < "05DC":
        if sap == "Global DSAP":
            output_file.write("IEEE 802.3 - Raw\n")

            sap = "IPX"

            has_ether_type = False
            has_sap = True
        elif sap == "SNAP":
            output_file.write("IEEE 802.3 - LLC + Snap\n")

            has_ether_type = True
            has_sap = True
        else:
            output_file.write("IEEE 802.3 - LLC\n")

            has_ether_type = False
            has_sap = True
    else:
        output_file.write("Ethernet II\n")

        has_ether_type = True
        has_sap = False

    output_file.write("Zdrojová MAC adresa: ")
    print_src_mac(output_file, packet_hex)
    output_file.write("Cieľová MAC adresa: ")
    print_dst_mac(output_file, packet_hex)

    if has_sap:
        if sap is not None:
            output_file.write(sap + "\n")
        else:
            output_file.write("undefined SAP\n")

    if has_ether_type:
        if ether_type is not None:
            output_file.write(ether_type + "\n")

            if ether_type == "IPv4":
                output_file.write("Zdrojová IP adresa: ")
                print_src_ip(output_file, packet_hex)
                output_file.write("Cieľová IP adresa: ")
                print_dst_ip(output_file, packet_hex)
        else:
            output_file.write("undefined ether type\n")

    print_frame(output_file, packet_hex)

    output_file.write("\n")


def analyze_packets(output_file, packets):
    packet_index = 0

    for packet in packets:
        packet_index += 1
        analyze_packet(output_file, packet, packet_index)

    print("Výstupný súbor bol vygenerovaný.")


while True:
    file_name = input("Názov čítaného súboru (s príponou): ")

    try:
        my_packets = rdpcap(file_name)
    except IOError:
        print("Zadaný súbor neexistuje.")
        continue

    outputFile = open("Výstup.txt", "w", encoding="utf-8")
    analyze_packets(outputFile, my_packets)
    outputFile.close()





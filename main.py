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


def get_ether_type(packet_hex):
    return packet_hex[24:28]


def get_dsap(packet_hex):
    return packet_hex[29:30]


def analyze_pcap(packets):
    output_file = open("Výstup.txt", "w", encoding="utf-8")
    packet_index = 0

    for packet in packets:
        packet_index += 1
        packet_bytes = raw(packet)
        packet_hex = packet_bytes.hex()

        packet_length = len(packet_bytes)
        real_packet_length = packet_length + 4
        if real_packet_length < 64:
            real_packet_length = 64

        output_file.write("rámec " + str(packet_index) + "\n")
        output_file.write("dĺžka rámca poskytnutá pcap API - " + str(packet_length) + " B\n")
        output_file.write("dĺžka rámca prenášaného po médiu - " + str(real_packet_length) + " B\n")

        ether_type = get_ether_type(packet_hex)
        if ether_type < "05dc":
            dsap = get_dsap(packet_hex)

            if dsap == "ff":
                output_file.write("IEEE 802.3 - Raw\n")
            elif dsap == "aa":
                output_file.write("IEEE 802.3 - LLC + Snap\n")
            else:
                output_file.write("IEEE 802.3 - LLC\n")

            is_ethernet = False
        else:
            output_file.write("Ethernet II\n")
            is_ethernet = True

        output_file.write("Zdrojová MAC adresa: ")
        print_src_mac(output_file, packet_hex)
        output_file.write("Cieľová MAC adresa: ")
        print_dst_mac(output_file, packet_hex)

        # IPv4 ether type
        if is_ethernet:
            if ether_type == "0800":
                output_file.write("IPv4\n")

            output_file.write("zdrojová IP adresa: \n")
            output_file.write("cieľová IP adresa: \n")

        print_frame(output_file, packet_hex)
        output_file.write("\n")

    output_file.close()
    print("Výstupný súbor bol vygenerovaný.")


while True:
    file_name = input("Názov čítaného súboru (s príponou): ")

    file_exists = True

    try:
        my_packets = rdpcap(file_name)
    except IOError:
        print("Zadaný súbor neexistuje.")
        continue

    analyze_pcap(my_packets)





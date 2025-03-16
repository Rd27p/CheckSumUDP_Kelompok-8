import struct
import socket

def ip_to_bytes(ip):
    try:
        return socket.inet_aton(ip)
    except socket.error:
        print(f"Error: IP address {ip} is invalid.")
        exit(1)

def hex_to_bytes(hex_data):
    try:
        return bytes.fromhex(hex_data)
    except ValueError:
        print("Error: Format data heksadesimal tidak valid.")
        exit(1)

def udp_checksum(source_ip, dest_ip, source_port, dest_port, data):
    pseudo_header = struct.pack('!4s4sBBH',
                                 ip_to_bytes(source_ip),
                                 ip_to_bytes(dest_ip),
                                 0, 
                                 socket.IPPROTO_UDP,
                                 len(data) + 8)
    
    udp_header = struct.pack('!HHHH',
                              source_port,
                              dest_port,
                              len(data) + 8,
                              0) 
    checksum_data = pseudo_header + udp_header + data
    
    if len(checksum_data) % 2 == 1:
        checksum_data += b'\x00'
    
    checksum = 0
    for i in range(0, len(checksum_data), 2):
        word = (checksum_data[i] << 8) + checksum_data[i + 1]
        checksum += word
        while checksum > 0xFFFF:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    checksum = ~checksum & 0xFFFF
    return checksum

if _name_ == "_main_":
    print("\n===================== UDP Checksum Calculator ======================")

    src_ip = input("Masukkan IP sumber: ").strip()
    dst_ip = input("Masukkan IP tujuan: ").strip()
    
    try:
        src_port = int(input("Masukkan Port sumber: ").strip())
        dst_port = int(input("Masukkan Port tujuan: ").strip())
    except ValueError:
        print("Error: Port harus berupa angka.")
        exit(1)

    data = input("Masukkan data yang akan dikirim: ").strip()
    
    if all(c in '0123456789ABCDEFabcdef ' for c in data):  
        data = hex_to_bytes(data)
    else:
        data = data.encode()

    checksum = udp_checksum(src_ip, dst_ip, src_port, dst_port, data)
    
    print("\n==================== Hasil Perhitungan Checksum ====================")
    print(f"UDP Checksum untuk {src_ip}:{src_port} -> {dst_ip}:{dst_port}: {hex(checksum)}\n")
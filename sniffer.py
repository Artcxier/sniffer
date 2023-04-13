import socket
import os

#host do nasłuchiwania
HOST = '192.168.0.203'

def main():
    #utworzenie surowego gniazda i powiązanie go z interfejsem publicznym
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))
    #przechywytywanie nagłówka IP
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    #wczytywanie pojedyńczego pakietu
    print(sniffer.recvfrom(65565))

    #jeśli używany jest system windows, wyłączamy tryb nieograniczony
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == '__main__':
    main()
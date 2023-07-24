from scapy.all import *

"""Захват сетевого трафика на выбранном интерфейсе и помещение захваченных пакетов в переменную"""
a = sniff(count=5)
wrpcap("our_dump.pcap", a)

"""Создаем объект средства чтения файлов .PCAP"""
packets = PcapReader("our_dump.pcap")

"""
Анализ IP-адресов и портов отправителей и получателей пакетов.
Выводим только интересующие нас пакеты.
"""
for packet in packets:
    if IP in packet:

        """Поиск аномалий, например, необычные порты или большое количество отправленных пакетов от одного источника"""
        if TCP in packet:
            if packet[TCP].dport > 1024:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport
                dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
                print(f"Source IP: {src_ip}, Source Port: {src_port}")
                print(f"Destination IP: {dst_ip}, Destination Port: {dst_port}")
                print("Аномальный порт TCP!")
                print('\n')
        elif UDP in packet:
            if packet[UDP].dport > 1024:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport
                dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
                print(f"Source IP: {src_ip}, Source Port: {src_port}")
                print(f"Destination IP: {dst_ip}, Destination Port: {dst_port}")
                print("Аномальный порт UDP!")
                print('\n')

        """Анализ типов протоколов и соответствующей информации о пакетах, а также большая длина пакетов """
        if TCP in packet and packet[TCP].window > 1000:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            print(f"Source IP: {src_ip}, Source Port: {src_port}")
            print(f"Destination IP: {dst_ip}, Destination Port: {dst_port}")
            print("Protocol: TCP")
            print(f"Аномальный размер > 1000: {packet[TCP].window}")
            print('\n')
        elif UDP in packet and packet[UDP].len > 1000:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            print(f"Source IP: {src_ip}, Source Port: {src_port}")
            print(f"Destination IP: {dst_ip}, Destination Port: {dst_port}")
            print("Protocol: UDP")
            print(f"Аномальный размер > 1000: {packet[UDP].len}")
            print('\n')

        """ Анализ трафика от одного источника, 192.168.1.1 - адрес маршрутизатора роутера """
        if packet[IP].src == "192.168.1.1":
            print("Высокий трафик!")

"""
Если требуется вывести как можно больше информации о каждом пакете, то следует вышенаписанный код заменить функцией .show():

for packet in packets:
    print(packet.show())
    
Доп задание, где нужно произвести фильтрацию пакетов:

sniff(filter = 'tcp port 110 or tcp port 25 or tcp port 143') - читай README
"""
from scapy.all import *

#Захват сетевого трафика на выбранном интерфейсе и помещение захваченных пакетов в переменную
a = sniff(count=500)
wrpcap("our_dump.pcap", a)
#Создаем объект средства чтения файлов .PCAP
packets = PcapReader("our_dump.pcap")
#Словарь флагов для просто отлавливания ошибки и более понятного вывода информации 
flags = {
            'F': 'FIN',
            'S': 'SYN',
            'R': 'RST',
            'P': 'PSH',
            'A': 'ACK',
            'U': 'URG',
            'E': 'ECE',
            'C': 'CWR',}
"""
Анализ IP-адресов и портов отправителей и получателей пакетов.
Выводим только интересующие нас пакеты.
"""
for packet in packets:
    #Нагрузка покета
    print(packet.payload)
    if IP in packet:
        #Запишем номер протокола и дадим ему значение 
        valueOfProto = packet[IP].proto
        if valueOfProto == 6:
            value = TCP
            name = "TCP"
            packet_Flag = [flags[x] for x in packet.sprintf('%TCP.flags%')]
            print("flags: ", *packet_Flag)
        elif valueOfProto == 17:
            value = UDP
            name = "UDP"
        #Обозначим источники и точки назначения для айпи и порта
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[value].sport
        dst_port = packet[value].dport
        """Поиск аномалий, например, необычные порты или большое количество отправленных пакетов от одного источника"""
        if packet[value].dport > 1024:
            print(f"Source IP: {src_ip}, Source Port: {src_port}")
            print(f"Destination IP: {dst_ip}, Destination Port: {dst_port}")
            print("Аномальный порт:", name)
            print('\n')
        
        """Анализ типов протоколов и соответствующей информации о пакетах, а также большая длина пакетов """
        if value == TCP and packet[TCP].window > 64240:                                                          #Отредактировано под запросы локального роутера с 1000, чтобы регистрировать потолок
            print(f"Source IP: {src_ip}, Source Port: {src_port}")
            print(f"Destination IP: {dst_ip}, Destination Port: {dst_port}")
            print(f"Аномальный размер > 64000: {packet[TCP].window}")
            print('\n')

        #по выявленной закономерности через вайршарк всё удп подключения с длинной >1000 были разорваны
        elif value == UDP in packet and packet[UDP].len > 1000:
            print(f"Source IP: {src_ip}, Source Port: {src_port}")
            print(f"Destination IP: {dst_ip}, Destination Port: {dst_port}")
            print(f"Аномальный размер > 1000: {packet[UDP].len}")
            print('\n')
        if 'RST' in packet_Flag:
            #Если программа встречает флаг RST(R) ловит и помечает данный пакет
            print("RST flag caught: packet got caught by a firewall or disruppted/sent to a closed socket")
        #Анализ трафика от одного источника, 192.168.1.1 - адрес маршрутизатора роутера
        if packet[IP].src == "192.168.1.1":
            print("Высокий трафик!")
        print("|__________________________________________________________|")

"""
Если требуется вывести как можно больше информации о каждом пакете, то следует вышенаписанный код заменить функцией .show():

for packet in packets:
    print(packet.show())
    
Доп задание, где нужно произвести фильтрацию пакетов:

sniff(filter = 'tcp port 110 or tcp port 25 or tcp port 143') - читай README
"""
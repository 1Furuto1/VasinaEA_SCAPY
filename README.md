# VasinaEA_SCAPY
Программа с использованием SCAPY для анализа сетевых пакетов

Scapy предназначен для манипулирования сетевыми пакетами, в нем достаточно много функций.

Я работала в среде разработки PyCharm на Windows, поэтому чтобы библиотека работала, сначала я установила ее через настройки PyCharm`а,
это можно сделать и через консоль PyCharm.

Для удобства анализа пакетов была использована программа Wireshark, которая помогала сверять информацию, проанализированную ей с информацией, которую выдавал SCAPY.

Захват сетевого трафика происходит при помощи функции sniff(), которая имеет в себе множетсво аргументов, таких как filter(фильтрация пакетов по заданным условиям),
count(колличество захвачиваемых пакетов), iface(наименование сетевого интерфейса, который нужно прослушать) и т.д.

Далее для удобства чтения собранных данных из файла я использую функцию PcapReader(filename).
В цикле for производится обработка полученных данных, отбор и анализ. По желанию можно добавлять if для вывода большей информации, которая вас может интересовать.
В данном случае я нахожу IP адреса отправителей и получаетей, их порты, протоколы, по которым работают пакеты и выявляю пакеты, которые могут быть подозрительными.

Для получения наибольшей информации о пакете существует функция .show(), которая выводит на экран всю информацию, которая может интересовать пользователя, в том 
числе всё то, что вручную выбо написано мной.

Т.к. все номера портов стандартизованы и нахождятся в диапазоне от 0 до 65535. Написанная программа проверяла номера портов, которые больше 1024(в диапазоне
от 0 до 1023 находятся "системные порты") и считала все порты, удовлетворяющие этому диапазону как аномальные для нашего случая.
В случае проверки размеров пакетов было выбрано число 1000, т.к. во многих случаях просматривая пакеты в Wireshark было замечено, что из 100 пакетов 6 из 
имели размер больше 1000. Пакеты с размером >1000 считались аномальными.

Обратите внимание на пример sniff(filter = 'tcp port 110 or tcp port 25 or tcp port 143')
Здесь отредактирована функция sniff, добавив в нее фильтр BPF, захватывающий только трафик, направленный на характерные для электронной
почты порты 110 (POP3), 143 (IMAP) и 25 (SMTP). По такому принципу можно фильтровать пакеты по любым запросам пользователя.
# ShulyakMA_SCAPY
Создана отдельная ветвь для локальных систем и более детальной проверки данных.

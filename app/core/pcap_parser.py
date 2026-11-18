import os
from datetime import datetime
from scapy.all import rdpcap, IP, TCP, UDP, ICMP

# Ограничения из ТЗ
ALLOWED_EXTENSIONS = (".pcap", ".pcapng")
MAX_FILE_SIZE_MB = 50

def parse_pcap(file_path: str) -> list[dict]:
    """
    Читает pcap-файл и возвращает список пакетов в виде словарей.
    :param file_path: путь к pcap-файлу на диске
    :return: список словарей, каждый словарь = один пакет
    """
    packets = rdpcap(file_path)  # читаем весь файл (список пакетов)
    result = []

    for pkt in packets:
        # нас интересуют только пакеты, у которых есть слой IP
        if not pkt.haslayer(IP):
            continue

        ip_layer = pkt[IP]

        # заготовка записи с общими полями
        record = {
            "timestamp": datetime.fromtimestamp(float(pkt.time)),
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "protocol": None,
            "src_port": None,
            "dst_port": None,
            "length": len(pkt),
            "tcp_flags": None,
        }

        # определяем протокол и порты
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            record["protocol"] = "TCP"
            record["src_port"] = int(tcp.sport)
            record["dst_port"] = int(tcp.dport)
            record["tcp_flags"] = str(tcp.flags)  # например 'S' = SYN
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            record["protocol"] = "UDP"
            record["src_port"] = int(udp.sport)
            record["dst_port"] = int(udp.dport)
        elif pkt.haslayer(ICMP):
            record["protocol"] = "ICMP"
        else:
            record["protocol"] = "OTHER"
        result.append(record)
    return result


def parse_pcap_safe(file_path: str) -> list[dict]:
    """
    Разбор pcap с проверками из ТЗ: расширение, размер, читаемость, непустота.
    При любой проблеме бросает ValueError с понятным текстом.
    """
    # 1. Расширение файла
    if not file_path.lower().endswith(ALLOWED_EXTENSIONS):
        raise ValueError("Допустимы только файлы .pcap и .pcapng")

    # 2. Файл существует и размер в пределах лимита
    if not os.path.isfile(file_path):
        raise ValueError("Файл не найден")
    if os.path.getsize(file_path) > MAX_FILE_SIZE_MB * 1024 * 1024:
        raise ValueError(f"Файл слишком большой (лимит {MAX_FILE_SIZE_MB} МБ)")

    # 3. Файл читается (pcap может быть битым)
    try:
        packets = parse_pcap(file_path)
    except Exception as e:
        raise ValueError(f"Не удалось разобрать pcap-файл: {e}")

    # 4. Файл не пустой
    if not packets:
        raise ValueError("В файле не найдено IP-пакетов")

    return packets

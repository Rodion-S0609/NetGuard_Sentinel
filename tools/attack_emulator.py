import argparse
import random
from scapy.all import IP, TCP, UDP, wrpcap

# --- Настройки "сети" ---

INTERNAL_NET = "192.168.1."          # внутренние адреса кофейни
VICTIM_SSH = "192.168.1.10"          # машина, которую брутфорсят (SSH)
VICTIM_WEB = "192.168.1.20"          # цель DDoS (веб-сервер)
ATTACKER_BRUTE = "203.0.113.5"       # источник брутфорса
BLACKLIST_IP = "45.155.205.100"      # адрес из чёрного списка (см. blacklist.txt)

def gen_normal(count=200, start_time=0.0):
    """Обычный трафик: внутренние адреса общаются по вебу."""
    packets = []
    t = start_time
    for _ in range(count):
        src = INTERNAL_NET + str(random.randint(2, 50))
        dst = INTERNAL_NET + str(random.randint(2, 50))
        pkt = IP(src=src, dst=dst) / TCP(sport=random.randint(1024, 65535),
                                         dport=random.choice([80, 443]),
                                         flags="PA")   # обычные данные
        pkt.time = t
        t += random.uniform(0.05, 0.3)                 # редко
        packets.append(pkt)
    return packets

def gen_bruteforce(count=50, start_time=100.0):
    """Брутфорс SSH: один источник, много SYN на порт 22 за короткое время."""
    packets = []
    t = start_time
    for _ in range(count):
        pkt = IP(src=ATTACKER_BRUTE, dst=VICTIM_SSH) / TCP(
            sport=random.randint(1024, 65535), dport=22, flags="S")  # SYN
        pkt.time = t
        t += 0.1                                        # 10 попыток в секунду
        packets.append(pkt)
    return packets

def gen_ddos(count=800, start_time=200.0):
    """DDoS: множество разных источников заваливают одну цель."""
    packets = []
    t = start_time
    for _ in range(count):
        src = f"{random.randint(1,223)}.{random.randint(0,255)}." \
              f"{random.randint(0,255)}.{random.randint(1,254)}"
        pkt = IP(src=src, dst=VICTIM_WEB) / TCP(
            sport=random.randint(1024, 65535), dport=80, flags="S")
        pkt.time = t
        t += 0.003                                      # очень часто
        packets.append(pkt)
    return packets

def gen_blacklist(count=5, start_time=300.0):
    """Соединение с адресом из чёрного списка."""
    packets = []
    t = start_time
    for _ in range(count):
        pkt = IP(src=INTERNAL_NET + "15", dst=BLACKLIST_IP) / TCP(
            sport=random.randint(1024, 65535), dport=443, flags="PA")
        pkt.time = t
        t += 1.0
        packets.append(pkt)
    return packets

def main():
    parser = argparse.ArgumentParser(description="Генератор демо-pcap с атаками")
    parser.add_argument("--out", default="sample_data/test.pcap",
                        help="куда сохранить pcap")
    args = parser.parse_args()
    all_packets = []
    all_packets += gen_normal()
    all_packets += gen_bruteforce()
    all_packets += gen_ddos()
    all_packets += gen_blacklist()
    # сортируем по времени (как в реальном захвате)
    all_packets.sort(key=lambda p: p.time)
    wrpcap(args.out, all_packets)
    print(f"Готово! Сохранено пакетов: {len(all_packets)} → {args.out}")
    print("Заложены атаки: брутфорс SSH, DDoS на веб, обращение к blacklist.")

if __name__ == "__main__":
    main()


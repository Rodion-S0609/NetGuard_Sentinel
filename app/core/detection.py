import os
from collections import defaultdict, deque
from datetime import timedelta
from app.models.threats import Threat

# --- Пороги детекции (можно калибровать) ---
# Брутфорс: сколько попыток подключения к одному (dst_ip, dst_port)
# с одного src_ip за окно времени считаем атакой

BRUTEFORCE_WINDOW_SEC = 10   # окно в секундах
BRUTEFORCE_THRESHOLD = 20    # порог: >20 попыток за 10 сек

# Порты, по которым обычно стучатся брутфорсом (для повышения severity)
SENSITIVE_PORTS = {22, 23, 3389, 3306, 5432, 21}  # SSH, Telnet, RDP, MySQL, Postgres, FTP

# DDoS/флуд: сколько пакетов на один dst_ip за окно считаем флудом
DDOS_WINDOW_SEC = 5
DDOS_THRESHOLD = 500         # порог: >500 пакетов за 5 сек на одну цель

# Флаг SYN-флуда: много SYN-пакетов без завершения соединения
SYN_FLOOD_THRESHOLD = 200    # >200 SYN за окно DDOS_WINDOW_SEC


def detect_bruteforce(packets: list[dict]) -> list[dict]:
    """
    Ищет брутфорс. Возвращает список найденных угроз (словарей).
    packets — список пакетов из parse_pcap, отсортированный по времени.
    """
    threats = []
    # для каждого ключа (src, dst, port) храним времена последних попыток
    windows = defaultdict(deque)
    # чтобы не создавать дубли угроз по одному ключу
    already_flagged = set()

    for p in packets:
        # брутфорс рассматриваем только для TCP-подключений (флаг SYN)
        if p["protocol"] != "TCP":
            continue
        if p["tcp_flags"] is None or "S" not in p["tcp_flags"]:
            continue

        key = (p["src_ip"], p["dst_ip"], p["dst_port"])
        t = p["timestamp"]

        dq = windows[key]
        dq.append(t)

        # убрать из окна всё, что старше BRUTEFORCE_WINDOW_SEC
        while dq and (t - dq[0]) > timedelta(seconds=BRUTEFORCE_WINDOW_SEC):
            dq.popleft()

        # если в окне слишком много попыток — это угроза
        if len(dq) > BRUTEFORCE_THRESHOLD and key not in already_flagged:
            already_flagged.add(key)
            port = p["dst_port"]
            severity = "high" if port in SENSITIVE_PORTS else "medium"
            threats.append({
                "threat_type": "bruteforce",
                "severity": severity,
                "src_ip": p["src_ip"],
                "dst_ip": p["dst_ip"],
                "dst_port": port,
                "packet_count": len(dq),
                "description": (
                    f"Обнаружен подбор пароля: {len(dq)} попыток подключения "
                    f"с {p['src_ip']} на {p['dst_ip']}:{port} "
                    f"за {BRUTEFORCE_WINDOW_SEC} сек."
                ),
            })

    return threats


def detect_ddos(packets: list[dict]) -> list[dict]:
    """
    Ищет DDoS/флуд по количеству пакетов на одну цель за окно времени.
    """
    threats = []
    windows = defaultdict(deque)       # dst_ip -> времена пакетов
    syn_windows = defaultdict(deque)   # dst_ip -> времена SYN-пакетов
    flagged_ddos = set()
    flagged_syn = set()

    for p in packets:
        dst = p["dst_ip"]
        t = p["timestamp"]

        # общий счётчик пакетов на цель
        dq = windows[dst]
        dq.append(t)
        while dq and (t - dq[0]) > timedelta(seconds=DDOS_WINDOW_SEC):
            dq.popleft()

        if len(dq) > DDOS_THRESHOLD and dst not in flagged_ddos:
            flagged_ddos.add(dst)
            threats.append({
                "threat_type": "ddos",
                "severity": "high",
                "src_ip": None,        # источников много
                "dst_ip": dst,
                "dst_port": p["dst_port"],
                "packet_count": len(dq),
                "description": (
                    f"Возможная DDoS-атака: {len(dq)} пакетов на {dst} "
                    f"за {DDOS_WINDOW_SEC} сек."
                ),
            })

        # отдельный счётчик SYN-пакетов (SYN-флуд)
        if p["protocol"] == "TCP" and p["tcp_flags"] and "S" in p["tcp_flags"]:
            sdq = syn_windows[dst]
            sdq.append(t)
            while sdq and (t - sdq[0]) > timedelta(seconds=DDOS_WINDOW_SEC):
                sdq.popleft()

            if len(sdq) > SYN_FLOOD_THRESHOLD and dst not in flagged_syn:
                flagged_syn.add(dst)
                threats.append({
                    "threat_type": "ddos",
                    "severity": "high",
                    "src_ip": None,
                    "dst_ip": dst,
                    "dst_port": p["dst_port"],
                    "packet_count": len(sdq),
                    "description": (
                        f"Возможный SYN-флуд: {len(sdq)} SYN-пакетов на {dst} "
                        f"за {DDOS_WINDOW_SEC} сек."
                    ),
                })

    return threats


def load_blacklist(path: str = "app/core/blacklist.txt") -> set[str]:
    """Читает файл чёрного списка в множество IP."""
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip() and not line.startswith("#")}


def detect_blacklist(packets: list[dict], blacklist: set[str]) -> list[dict]:
    """
    Ищет обращения к/от IP из чёрного списка.
    """
    threats = []
    flagged = set()   # чтобы не плодить дубли по одному bad_ip

    for p in packets:
        bad_ip = None
        if p["src_ip"] in blacklist:
            bad_ip = p["src_ip"]
        elif p["dst_ip"] in blacklist:
            bad_ip = p["dst_ip"]

        if bad_ip and bad_ip not in flagged:
            flagged.add(bad_ip)
            threats.append({
                "threat_type": "blacklist",
                "severity": "high",
                "src_ip": p["src_ip"],
                "dst_ip": p["dst_ip"],
                "dst_port": p["dst_port"],
                "packet_count": 1,
                "description": f"Обнаружено соединение с адресом из чёрного списка: {bad_ip}.",
            })

    return threats

def run_detection(packets: list[dict]) -> list[dict]:
    """
    Запускает все детекторы и возвращает общий список угроз.
    packets — список пакетов из parse_pcap.
    """
    # сортируем по времени (важно для оконных алгоритмов)
    packets = sorted(packets, key=lambda p: p["timestamp"])
    blacklist = load_blacklist()

    threats = []
    threats += detect_bruteforce(packets)
    threats += detect_ddos(packets)
    threats += detect_blacklist(packets, blacklist)
    return threats

def save_threats(db, capture_id: int, threats: list[dict]) -> int:
    objects = [Threat(capture_id=capture_id, **t) for t in threats]
    db.bulk_save_objects(objects)
    db.commit()
    return len(objects)

def calculate_status(threats: list[dict]) -> str:
    """
    Возвращает общий статус сети:
    - 'red'    — есть хотя бы одна угроза severity=high
    - 'yellow' — есть угрозы, но только low/medium
    - 'green'  — угроз нет
    """
    if not threats:
        return "green"
    if any(t["severity"] == "high" for t in threats):
        return "red"
    return "yellow"

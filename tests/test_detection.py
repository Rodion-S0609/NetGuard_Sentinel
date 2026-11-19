import os
import random
from datetime import datetime, timedelta
from app.core.detection import detect_bruteforce, calculate_status, detect_ddos, load_blacklist, detect_blacklist

def make_packet(src, dst, port, t, flags="S"):
    return {
        "timestamp": t, "src_ip": src, "dst_ip": dst,
        "src_port": 50000, "dst_port": port, "protocol": "TCP",
        "length": 60, "tcp_flags": flags,
    }

def test_bruteforce_detected():
    base = datetime(2026, 1, 1, 12, 0, 0)
    # 30 попыток на порт 22 за 5 секунд -> должно сработать
    packets = [make_packet("10.0.0.5", "10.0.0.1", 22, base + timedelta(seconds=i*0.1))
               for i in range(30)]
    threats = detect_bruteforce(packets)
    assert len(threats) >= 1
    assert threats[0]["threat_type"] == "bruteforce"
    assert threats[0]["severity"] == "high"   # порт 22 — чувствительный

def test_status_green_when_no_threats():
    assert calculate_status([]) == "green"

def test_ddos_detected():
    # Генерируем 501 пакет (превышаем порог DDOS_THRESHOLD = 500)
    # Все пакеты летят на один dst_ip за короткое время
    base_time = datetime.now()
    packets = []
    for i in range(501):
        packets.append({
            "timestamp": base_time + timedelta(milliseconds=i), # все за 1 секунду
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.100",
            "protocol": "TCP",
            "dst_port": 80,
            "tcp_flags": "A" 
        })
    
    threats = detect_ddos(packets)
    
    assert len(threats) > 0
    assert threats[0]["threat_type"] == "ddos"
    assert threats[0]["severity"] == "high"
    
def test_detect_entire_real_blocklist():
    """
    Тест:
    1. Генерирует случайный IP-адрес источника.
    2. Читает весь файл blocklist.txt.
    3. Создает пакеты для КАЖДОГО IP из списка.
    4. Проверяет, что детектор нашел все угрозы без исключения.
    """
    # 1. Проверяем наличие файла
    file_path = "app/core/blacklist.txt"
    assert os.path.exists(file_path), (
        f"ОШИБКА: Файл не найден по пути '{file_path}'."
    )

    # 2. Читаем реальный черный список
    real_blocklist = load_blacklist(path=file_path)
    assert len(real_blocklist) > 0, (
        "ОШИБКА: Файл blocklist.txt пуст. Добавьте в него IP-адреса."
    )

    # 3. Генерируем случайный IP-адрес источника (например, от 2 до 254)
    generated_src_ip = f"192.168.1.{random.randint(2, 254)}"

    # 4. Создаем пакеты для ВСЕХ IP из черного списка
    packets = []
    for bad_ip in real_blocklist:
        packets.append({
            "timestamp": datetime.now(),
            "src_ip": generated_src_ip,  # Наш сгенерированный IP
            "dst_ip": bad_ip,            # IP из черного списка
            "protocol": "TCP",
            "dst_port": 80,
            "tcp_flags": "S"
        })

    # 5. Запускаем детектор
    threats = detect_blacklist(packets, real_blocklist)

    # 6. Проверяем, что количество найденных угроз совпадает с размером списка
    assert len(threats) == len(real_blocklist), (
        f"ОШИБКА: Детектор нашел {len(threats)} угроз, "
        f"а в черном списке {len(real_blocklist)} адресов."
    )

    # 7. Проверяем, что каждый IP из списка действительно был найден
    detected_ips = {threat["dst_ip"] for threat in threats}
    assert detected_ips == real_blocklist, (
        "ОШИБКА: Некоторые IP из черного списка не были обнаружены детектором."
    )

    # Выводим результат при запуске с флагом -s
    print(f"\n✅ Успешно: Сгенерирован источник {generated_src_ip}. "
          f"Проверены все {len(real_blocklist)} адресов из blacklist.txt.")        

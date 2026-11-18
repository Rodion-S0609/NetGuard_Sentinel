from sqlalchemy.orm import Session
from app.models.packets import Packet
from app.models.captures import Capture

def save_packets(db: Session, capture_id: int, packets: list[dict]) -> int:
    """
    Сохраняет список пакетов в БД пачкой (bulk).
    :return: количество сохранённых пакетов
    """
    if not packets:
        return 0
    objects = [
        Packet(
            capture_id=capture_id,
            timestamp=p["timestamp"],
            src_ip=p["src_ip"],
            dst_ip=p["dst_ip"],
            src_port=p["src_port"],
            dst_port=p["dst_port"],
            protocol=p["protocol"],
            length=p["length"],
            tcp_flags=p["tcp_flags"],
        )
        for p in packets
    ]
    try:
        # bulk_save_objects — быстрая вставка большого числа строк
        db.bulk_save_objects(objects)
        db.commit()
    except Exception:
        db.rollback()  # не оставляем сессию в сломанном состоянии
        raise

    return len(objects)

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from app.config import get_settings

# базовый класс для всех моделей
class Base(DeclarativeBase):
    pass

# "движок" — соединение с PostgreSQL, адрес берём из настроек
engine = create_engine(get_settings().database_url, pool_pre_ping=True)

# фабрика сессий: через сессию мы читаем/пишем данные
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# вспомогательная функция для FastAPI: даёт сессию и закрывает её
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
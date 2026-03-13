import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.models import Base

# 컨테이너 환경변수에서 로드, 기본값은 localhost (Host Network 기반 스캐너 동작 시)
DB_USER = os.getenv("DB_USER", "asm_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "asm_password_secure")
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "asm_db")

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """데이터베이스 연결 테스트 및 Base 모델 메타데이터를 사용하여 테이블을 생성(또는 반영)합니다."""
    print(f"[*] 데이터베이스 초기화 시도: {DB_HOST}:{DB_PORT}")
    try:
        # DB 테이블 생성 (이미 존재하면 무시)
        Base.metadata.create_all(bind=engine)
        print("[+] ASM Database 스키마가 성공적으로 생성되었습니다.")
    except Exception as e:
        print(f"[-] Database 초기화 실패: {e}")

if __name__ == "__main__":
    init_db()

from datetime import datetime,timezone
from sqlalchemy import create_engine,JSON,DateTime,Integer,String,select
from sqlalchemy.orm import DeclarativeBase,Mapped,Session,mapped_column,sessionmaker
from .config import get_settings
s=get_settings(); args={"check_same_thread":False} if s.database_url.startswith("sqlite") else {}
engine=create_engine(s.database_url,pool_pre_ping=True,connect_args=args); SessionLocal=sessionmaker(bind=engine)
class Base(DeclarativeBase): pass
class AuditRecord(Base):
 __tablename__="audit_events"; id:Mapped[int]=mapped_column(Integer,primary_key=True); request_id:Mapped[str]=mapped_column(String(64),index=True); principal:Mapped[str]=mapped_column(String(255)); resource:Mapped[str]=mapped_column(String(255)); action:Mapped[str]=mapped_column(String(100)); decision:Mapped[str]=mapped_column(String(32)); risk_score:Mapped[int]=mapped_column(Integer); findings:Mapped[list]=mapped_column(JSON); timestamp:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
def init_db(): Base.metadata.create_all(engine)
def get_db():
 db=SessionLocal()
 try: yield db
 finally: db.close()
def save(db,e): db.add(AuditRecord(request_id=e.request_id,principal=e.principal,resource=e.resource,action=e.action,decision=e.decision.value,risk_score=e.risk_score,findings=[x.model_dump() for x in e.findings],timestamp=e.timestamp)); db.commit()
def recent(db,limit=50): return db.scalars(select(AuditRecord).order_by(AuditRecord.timestamp.desc()).limit(min(limit,200))).all()

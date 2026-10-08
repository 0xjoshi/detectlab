from app.database import Base, engine
from app.models import Host


Base.metadata.create_all(bind=engine)

print("Database initialized successfully.")
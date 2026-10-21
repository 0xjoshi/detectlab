
from app.database import Base, engine
from app.models import Host, Rule  # noqa: F401


Base.metadata.create_all(bind=engine)

print("Database initialized successfully.")

from fastapi import FastAPI

from app.api.hosts import router as hosts_router


app = FastAPI(
    title="DetectLab",
    description="Security Detection Testing & Log Analysis Platform",
    version="0.1.0",
)


@app.get("/health", tags=["system"])
def health_check():
    return {"status": "ok"}


app.include_router(hosts_router)
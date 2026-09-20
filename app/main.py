from fastapi import FastAPI

app = FastAPI(
    title="DetectLab",
    description="Security Detection Testing & Log Analysis Platform",
    version="0.1.0",
)


@app.get("/health")
def health_check():
    return {"status": "ok"}
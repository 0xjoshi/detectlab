from fastapi import FastAPI
from app.api.scenarios import router as scenarios_router
from app.api.events import router as events_router
from app.api.hosts import router as hosts_router
from app.api.rules import router as rules_router
from app.api.detections import router as detections_router
from app.api.coverage import router as coverage_router
from app.api.regressions import router as regressions_router

app = FastAPI(
    title="DetectLab",
    description="Security Detection Testing & Log Analysis Platform",
    version="0.1.0",
)


@app.get("/health", tags=["system"])
def health_check():
    return {"status": "ok"}


app.include_router(hosts_router)
app.include_router(rules_router)
app.include_router(events_router)
app.include_router(detections_router)
app.include_router(scenarios_router)
app.include_router(coverage_router)
app.include_router(regressions_router)
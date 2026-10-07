from fastapi import FastAPI

from api.config import settings


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Evidence-first security operations workbench",
)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "service": settings.app_name.lower().replace(" ", "-"),
        "version": settings.app_version,
    }
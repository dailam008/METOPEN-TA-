from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from app.database import get_db, init_db
from app.models import VTAPIKey, APIUsageLog
from app.config import settings
from app.api import keys, scan, dashboard
from app.api.api_router import router as api_router
from app.scheduler import start_scheduler, stop_scheduler
import uvicorn

app = FastAPI(
    title="VT Proxy Balancer",
    description="Multi-key VirusTotal API proxy with load balancing",
    version="1.0.0"
)

# ========== CORS ==========
_ALLOW_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    # Tambahkan origin internal lainnya di sini
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "x-apikey"],
)

# ========== ROUTERS ==========
app.include_router(keys.router)       # /keys/*  (legacy)
app.include_router(scan.router)       # /scan/*  (legacy + /scan/multi)
app.include_router(dashboard.router)  # /dashboard/* (legacy)
app.include_router(api_router)        # /api/* (clean, baru)

# ========== EVENTS ==========
@app.on_event("startup")
def startup():
    init_db()
    start_scheduler()
    print("[STARTUP] Database initialized! Scheduler started!")

@app.on_event("shutdown")
def shutdown():
    stop_scheduler()
    print("[SHUTDOWN] Scheduler stopped!")

# ========== ENDPOINTS ==========
@app.get("/")
def root():
    return {
        "message": "VT Proxy Balancer is alive!",
        "status": "operational",
        "version": "1.0.0"
    }

@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    total_keys = db.query(VTAPIKey).count()
    active_keys = db.query(VTAPIKey).filter(VTAPIKey.is_active == True).count()
    return {
        "status": "healthy",
        "total_keys": total_keys,
        "active_keys": active_keys
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
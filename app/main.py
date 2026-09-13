from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from app.database import get_db, init_db
from app.models import VTAPIKey, APIUsageLog
from app.config import settings
from app.api import keys, scan, dashboard
from app.scheduler import start_scheduler, stop_scheduler
import uvicorn

app = FastAPI(
    title="VT Proxy Balancer",
    description="Multi-key VirusTotal API proxy with load balancing",
    version="1.0.0"
)

# ========== CORS ==========
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== ROUTERS ==========
app.include_router(keys.router)
app.include_router(scan.router)
app.include_router(dashboard.router)

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
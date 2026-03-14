from fastapi import FastAPI, Depends, UploadFile, File, Form, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from typing import List, Optional, Annotated
from contextlib import asynccontextmanager
import sqlite3
import os
import shutil

import database
import schemas
import crud

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize database
    database.init_db()
    yield
    # Shutdown: Clean up if needed
    pass

app = FastAPI(title="Scam Reporting Platform API", lifespan=lifespan)

# Setup CORS for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, replace with frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create uploads directory if it doesn't exist
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Dependency to get DB connection
def get_db():
    db = sqlite3.connect(database.DATABASE_URL, check_same_thread=False)
    db.row_factory = sqlite3.Row
    try:
        yield db
    finally:
        db.close()

@app.post("/api/reports", response_model=schemas.ScamReportResponse, status_code=status.HTTP_201_CREATED)
async def create_report(
    scam_type: str = Form(...),
    description: str = Form(...),
    target_phone: Optional[str] = Form(None),
    target_email: Optional[str] = Form(None),
    target_website: Optional[str] = Form(None),
    screenshot: Optional[UploadFile] = File(None),
    db: Annotated[sqlite3.Connection, Depends(get_db)] = Depends(get_db)
):
    screenshot_path = None
    if screenshot and screenshot.filename:
        file_location = os.path.join(UPLOAD_DIR, screenshot.filename)
        with open(file_location, "wb+") as file_object:
            shutil.copyfileobj(screenshot.file, file_object)
        screenshot_path = file_location

    report = crud.create_scam_report(
        db=db,
        scam_type=scam_type,
        description=description,
        screenshot_path=screenshot_path,
        target_phone=target_phone,
        target_email=target_email,
        target_website=target_website
    )
    return dict(report)

@app.get("/api/search", response_model=List[schemas.ScamReportResponse])
def search_reports(query: str, db: sqlite3.Connection = Depends(get_db)):
    if not query:
        return []
    reports = crud.search_reports(db, query)
    return [dict(r) for r in reports]

@app.get("/api/stats/heatmap")
def get_heatmap(db: sqlite3.Connection = Depends(get_db)):
    stats = crud.get_heatmap_stats(db)
    return [{"scam_type": row["scam_type"], "count": row["count"]} for row in stats]

@app.post("/api/reports/{report_id}/verify", response_model=schemas.ScamReportResponse)
def verify_report(report_id: int, vote: schemas.VoteRequest, db: sqlite3.Connection = Depends(get_db)):
    updated_report = crud.vote_scam(db, report_id, vote.vote_type)
    if not updated_report:
        raise HTTPException(status_code=404, detail="Report not found or invalid vote type")
    return dict(updated_report)

@app.get("/api/tips", response_model=List[schemas.SafetyTipResponse])
def get_tips(db: sqlite3.Connection = Depends(get_db)):
    tips = crud.get_safety_tips(db)
    return [dict(t) for t in tips]

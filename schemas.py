from __future__ import annotations
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional

# Schema for Scam Reports
class ScamReportCreate(BaseModel):
    scam_type: str = Field(..., description="Type of scam (e.g., Online Shopping, Job, OTP, Investment, Other)")
    description: str = Field(..., description="Detailed description of the scam")
    # Note: screenshot will be handled via UploadFile in FastAPI, not in this Pydantic model
    target_phone: Optional[str] = Field(None, description="Phone number involved in the scam")
    target_email: Optional[str] = Field(None, description="Email address involved in the scam")
    target_website: Optional[str] = Field(None, description="Website link involved in the scam")

class ScamReportResponse(ScamReportCreate):
    id: int
    screenshot_path: Optional[str] = None
    experienced_count: int
    suspicious_count: int
    created_at: str

    model_config = ConfigDict(from_attributes=True)

# Schema for Safety Tips
class SafetyTipResponse(BaseModel):
    id: int
    title: str
    content: str
    category: str

    model_config = ConfigDict(from_attributes=True)

# Schema for Voting
class VoteRequest(BaseModel):
    vote_type: str = Field(..., description="'experienced' or 'suspicious'")

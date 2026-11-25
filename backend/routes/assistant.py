"""
AI Security Assistant API Routes for MiniSIEM X
Chat with local explanation engine, query MITRE techniques, and draft incident briefs.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.schemas import AssistantMessage, AssistantResponse
from backend.services.explanation_service import LocalDeterministicAssistant
from backend.detection.mitre_mapping import get_all_mitre_mappings

router = APIRouter(prefix="/api/assistant", tags=["Assistant"])

@router.post("/chat", response_model=AssistantResponse)
def chat_with_assistant(
    msg: AssistantMessage,
    db: Session = Depends(get_db)
):
    """Answers analyst questions using verified log evidence and MITRE playbooks."""
    response = LocalDeterministicAssistant.query(
        message=msg.message,
        context_type=msg.context_type,
        context_id=msg.context_id,
        db=db
    )
    return response

@router.get("/mitre")
def get_mitre_techniques():
    """Returns official MITRE ATT&CK technique catalog used across detection rules."""
    return get_all_mitre_mappings()


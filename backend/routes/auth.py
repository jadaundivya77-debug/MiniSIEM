"""
Authentication & User Management Routes for MiniSIEM X
Implements secure JWT token issue, role verification, and audit logging.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any
from backend.database import get_db
from backend.models import User, AuditLog
from backend.schemas import UserLogin, Token, UserResponse, UserCreate
from backend.utils.security import verify_password, hash_password, create_access_token, decode_access_token

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

def get_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> User:
    """Dependency to retrieve authenticated user from Bearer token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication token"
        )
    token = authorization.split(" ")[1]
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token"
        )
    username = payload["sub"]
    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found or disabled"
        )
    return user

@router.post("/login", response_model=Token)
def login(login_data: UserLogin, db: Session = Depends(get_db)):
    """Authenticates credentials and returns a signed JWT access token."""
    user = db.query(User).filter(User.username == login_data.username).first()
    if not user or not verify_password(login_data.password, user.hashed_password):
        # Record failed auth audit
        db.add(AuditLog(
            username=login_data.username,
            action="LOGIN_FAILURE",
            resource_type="USER",
            details="Invalid credentials submitted"
        ))
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated"
        )

    # Issue token
    token_payload = {
        "sub": user.username,
        "role": user.role,
        "email": user.email,
        "full_name": user.full_name
    }
    access_token = create_access_token(token_payload)

    # Audit log
    db.add(AuditLog(
        user_id=user.id,
        username=user.username,
        action="LOGIN_SUCCESS",
        resource_type="USER",
        details=f"Successful login. Assigned role: {user.role}"
    ))
    db.commit()

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role
        }
    }

@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Returns profile information for the authenticated user."""
    return current_user

@router.post("/logout")
def logout(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Logs out the active session and creates an audit entry."""
    db.add(AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="LOGOUT",
        resource_type="USER",
        details="Session terminated by user"
    ))
    db.commit()
    return {"status": "success", "message": "Logged out successfully"}


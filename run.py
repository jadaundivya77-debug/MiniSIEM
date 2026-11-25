"""
MiniSIEM X Runner Script
Starts the FastAPI application with Uvicorn and launches the SOC Web Portal.
"""
import uvicorn
import os
import sys

def main():
    print("=" * 60)
    print("   MiniSIEM X - Intelligent Security Monitoring Platform")
    print("      'See Threats. Understand Risks. Respond Smarter.'")
    print("=" * 60)
    print("\n[+] Initializing database schema and baseline detection rules...")
    
    from backend.database import init_db
    init_db()
    
    print("[+] Database initialized successfully.")
    print("[+] SOC Portal:   http://127.0.0.1:8000")
    print("[+] API Docs:     http://127.0.0.1:8000/docs")
    print("[+] Demo Logins:  admin / Admin@MiniSIEM2026! (Super Admin)")
    print("                  analyst / Analyst@2026! (Security Analyst)")
    print("                  viewer / Viewer@2026! (Auditor)\n")
    print("[*] Starting Uvicorn ASGI server...")
    
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)

if __name__ == "__main__":
    main()


from fastapi import FastAPI
from pulpo_governance.api.audit_api import router as audit_router

app = FastAPI()
app.include_router(audit_router)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import auth

app = FastAPI(
    title="TaskKey API",
    version="0.1.0",
    description="Backend API for TaskKey",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Routers ---
app.include_router(auth.router)


@app.get("/")
async def root():
    return {"message": "Welcome to TaskKey API"}

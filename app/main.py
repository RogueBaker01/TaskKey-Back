from fastapi import FastAPI

app = FastAPI(
    title="TaskKey API",
    version="0.1.0",
    description="Backend API for TaskKey — task management application.",
)


@app.get("/")
async def root():
    return {"message": "Welcome to TaskKey API"}

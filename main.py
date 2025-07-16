
from fastapi import FastAPI
from interfaces.api import router as task_router
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(title="To-Do List")
app.include_router(task_router)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"],  
)
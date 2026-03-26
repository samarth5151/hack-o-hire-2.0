from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import shutil
import os
import time

from attachment_main import analyze_attachment

app = FastAPI(title="Attachment Scanner API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

TEMP_DIR = "temp_uploads"
os.makedirs(TEMP_DIR, exist_ok=True)

@app.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):
    start_time = time.time()
    
    file_path = os.path.join(TEMP_DIR, file.filename)
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        with open(file_path, "rb") as f:
            file_bytes = f.read()
            
        # Run static analysis
        result = analyze_attachment(file_bytes, file.filename)
        
        # Add placeholder for the upcoming LLM content analysis module
        result["content_analysis"] = {
            "status": "pending",
            "score": None,
            "notes": "Waiting for LLM module integration..."
        }
        
        result["analysis_time_ms"] = round((time.time() - start_time) * 1000, 1)
        
        return result
        
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8007, reload=False)

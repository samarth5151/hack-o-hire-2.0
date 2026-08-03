# Start all AegisAI services natively for dev mode

Write-Host "Starting AegisAI dev environment..." -ForegroundColor Cyan

# Start Frontend
Start-Process powershell -ArgumentList "-NoExit -Command `"cd d:\Hack-o-hire-2\Frontend; npm install; npm run dev`"" -WindowStyle Normal

# Start DLP Gateway
Start-Process powershell -ArgumentList "-NoExit -Command `"cd d:\Hack-o-hire-2\dlp-gateway; python -m venv venv; .\venv\Scripts\Activate.ps1; pip install -r requirements.txt; uvicorn gateway.main:app --host 0.0.0.0 --port 8001`"" -WindowStyle Normal

# Start Sandbox Harness
Start-Process powershell -ArgumentList "-NoExit -Command `"cd d:\Hack-o-hire-2\sandbox; python -m venv venv; .\venv\Scripts\Activate.ps1; pip install -r requirements.txt; uvicorn harness.main:app --host 0.0.0.0 --port 8000`"" -WindowStyle Normal

Write-Host "Services are starting in new windows." -ForegroundColor Green
Write-Host "UI will be at http://localhost:5173" -ForegroundColor Yellow

$ErrorActionPreference = "Stop"
Write-Host "[1/3] Installing dependencies..."
python -m ensurepip --upgrade
python -m pip install -r requirements.txt
Write-Host "[2/3] Running tests..."
python test_cases.py
Write-Host "[3/3] Starting Streamlit..."
python -m streamlit run app.py

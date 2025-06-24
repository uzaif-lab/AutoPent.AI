#!/usr/bin/env python3
"""
Quick start script for AutoPent.AI Streamlit UI
"""
import subprocess
import sys
from pathlib import Path

def main():
    """Run the Streamlit application"""
    # Get the streamlit app path
    app_path = Path(__file__).parent / "streamlit_ui" / "app.py"
    
    if not app_path.exists():
        print(f"❌ Streamlit app not found at: {app_path}")
        sys.exit(1)
    
    print("🚀 Starting AutoPent.AI Web Interface...")
    print("🌐 Opening browser at: http://localhost:8501")
    print("⏹️  Press Ctrl+C to stop the server")
    
    try:
        # Run streamlit
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", 
            str(app_path),
            "--server.port", "8501",
            "--server.address", "localhost"
        ])
    except KeyboardInterrupt:
        print("\n👋 AutoPent.AI stopped. Thanks for using!")
    except Exception as e:
        print(f"❌ Failed to start Streamlit: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
#!/usr/bin/env python3
"""
AutoPent.AI Web Application Launcher
Launch the Flask web application locally
"""

import os
import sys
from api.main import app

def main():
    """Launch the web application"""
    print("🛡️  AutoPent.AI Web Application")
    print("=" * 40)
    print("🌐 Starting web server...")
    print("📱 Access the application at: http://localhost:5000")
    print("ℹ️  Development mode - ignore Flask warnings")
    print("⏹️  Press Ctrl+C to stop the server")
    print()
    
    # Run the Flask app (warnings are normal for development)
    try:
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=False  # Disable debug to reduce warnings
        )
    except KeyboardInterrupt:
        print("\n👋 AutoPent.AI stopped. Thanks for using!")

if __name__ == '__main__':
    main() 
#!/usr/bin/env python3
"""Minimal debug app to test what's failing in HuggingFace Space."""

from fastapi import FastAPI
import traceback

app = FastAPI(title="Debug WebSecCheck")

@app.get("/debug")
async def debug():
    """Debug endpoint to check what's working."""
    results = {"status": "testing"}
    
    # Test 1: Basic imports
    try:
        import aiohttp, dns.resolver, pydantic, reportlab, requests
        results["imports"] = "OK"
    except Exception as e:
        results["imports"] = f"FAIL: {e}"
    
    # Test 2: Checks imports
    try:
        from checks import ssl_tls, dns_records
        results["checks"] = "OK"
    except Exception as e:
        results["checks"] = f"FAIL: {e}"
        results["checks_traceback"] = traceback.format_exc()
    
    # Test 3: New modules
    try:
        from token_manager import generate_token
        from email_sender import send_report_email
        from report_html import generate_report_html
        results["new_modules"] = "OK"
    except Exception as e:
        results["new_modules"] = f"FAIL: {e}"
        results["new_modules_traceback"] = traceback.format_exc()
    
    # Test 4: Data directory
    try:
        import os
        data_dir = os.path.join(os.path.dirname(__file__), "data")
        results["data_dir_exists"] = os.path.exists(data_dir)
        results["current_dir"] = os.getcwd()
        results["file_list"] = os.listdir(".")[:10]  # First 10 files
    except Exception as e:
        results["filesystem"] = f"FAIL: {e}"
    
    return results

@app.get("/health")
async def health():
    return {"status": "debug_healthy"}
#!/usr/bin/env python3
"""Utility functions for WPA Hunter"""

import os
import sys
import termios
import subprocess
from datetime import datetime

def clear_input_buffer():
    """Clear terminal input buffer"""
    try:
        termios.tcflush(sys.stdin, termios.TCIFLUSH)
    except:
        pass

def validate_file(filepath, extension=None):
    """Validate if file exists and has correct extension"""
    if not os.path.exists(filepath):
        return False, f"File not found: {filepath}"
    
    if extension and not filepath.endswith(extension):
        return False, f"File must have {extension} extension"
    
    if os.path.getsize(filepath) == 0:
        return False, f"File is empty: {filepath}"
    
    return True, "OK"

def get_timestamp():
    """Get formatted timestamp"""
    return datetime.now().strftime('%Y%m%d_%H%M%S')

def check_root():
    """Check if running as root"""
    if os.geteuid() != 0:
        from rich.console import Console
        console = Console()
        console.print("[bold red][✗] This script must be run as root![/bold red]")
        return False
    return True

def kill_process(process, timeout=2):
    """Safely kill a subprocess"""
    if process and process.poll() is None:
        try:
            process.terminate()
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        return True
    return False
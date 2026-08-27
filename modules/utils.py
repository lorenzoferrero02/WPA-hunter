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
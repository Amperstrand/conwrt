#!/usr/bin/env python3
"""Thin shim — kept for backwards compatibility and direct invocation.

Usage: python3 scripts/fieldlab.py inspect --host root@192.168.1.1
"""
from fieldlab import main

main()

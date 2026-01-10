#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Configuration module for FTE.

This module provides runtime configuration storage and access
for the FTE library.
"""

import sys
from pathlib import Path


def getValue(key: str):
    """Get a configuration value by key.
    
    Args:
        key: The configuration key to look up.
        
    Returns:
        The configuration value associated with the key.
        
    Raises:
        KeyError: If the key doesn't exist.
    """
    return conf[key]


def setValue(key: str, value) -> None:
    """Set a configuration value.
    
    Args:
        key: The configuration key.
        value: The value to store.
    """
    conf[key] = value


def we_are_frozen() -> bool:
    """Check if the application is frozen (e.g., by PyInstaller).
    
    Returns:
        True if running as a frozen executable, False otherwise.
    """
    return hasattr(sys, "frozen")


def module_path() -> Path:
    """Get the path to the module directory.
    
    Returns:
        Path to the module's directory.
    """
    if we_are_frozen():
        return Path(sys.executable).parent
    else:
        return Path(__file__).parent


# Configuration storage
conf: dict = {}

# The base path for the location of the fte.* modules
if we_are_frozen():
    conf['general.base_dir'] = str(module_path())
else:
    conf['general.base_dir'] = str(module_path().parent)

# The path for fte *.json definition files
if we_are_frozen():
    conf['general.defs_dir'] = str(module_path() / 'fte' / 'defs')
else:
    conf['general.defs_dir'] = str(module_path().parent / 'fte' / 'defs')

# Log level: 0=silent, 1=normal, 2=verbose
conf['runtime.loglevel'] = 1

# The default AE scheme key (16 bytes of 0xFF + 16 bytes of 0x00)
conf['runtime.fte.encrypter.key'] = b'\xFF' * 16 + b'\x00' * 16

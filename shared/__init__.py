"""
PhantomCore Shared Module
=========================

Common utilities, models, and configuration management shared across
all PhantomCore toolkit modules (Spectra, Cipher, Morph, Nexus, Pulse).
"""

from shared.config import PhantomConfig, get_config

__all__ = ["PhantomConfig", "get_config"]

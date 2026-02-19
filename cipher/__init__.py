"""
PhantomCore Cipher -- Cryptographic Analysis Framework
=======================================================

Tool 2 of the PhantomCore cybersecurity educational toolkit.
Provides entropy analysis, hash identification, TLS cipher suite
evaluation, password strength assessment, frequency analysis,
cryptographic key strength estimation, and RNG statistical testing.

Modules:
    - cipher.core.engine: Central analysis orchestrator
    - cipher.core.models: Pydantic data models
    - cipher.analyzers: Individual analysis modules
    - cipher.parsers: Input parsing utilities
    - cipher.output: Console and report output
    - cipher.cli: Click-based command-line interface

References:
    - Shannon, C. E. (1948). A Mathematical Theory of Communication.
    - NIST SP 800-22 (2010). Statistical Test Suite for RNG.
    - NIST SP 800-131A (2019). Cryptographic Algorithm Transitions.
    - NIST SP 800-63B (2017). Digital Identity Guidelines.
"""

__version__ = "1.0.0"
__tool_name__ = "cipher"

"""
SRI-Xades-Signer
----------------

A Python library to generate XML digital signatures (XAdES-BES) compliant with
Ecuador's SRI electronic invoicing requirements.

Main entry points:
    - XadesSigner: reusable class to load a PKCS#12 and sign multiple XML docs.
    - sign_xml: helper function for one-off signing.
    - sign_and_save: sign and save the result to a file.
    - SignatureError: custom exception for signature errors.
"""

from .signer import (
    XadesSigner,
    sign_xml,
    sign_and_save,
    SignatureError,
)

__all__ = [
    "XadesSigner",
    "sign_xml",
    "sign_and_save",
    "SignatureError",
]

__version__ = "0.1.0"

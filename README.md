# SRI-Xades-Signer

Python library to sign XML with the XAdES-BES standard, in compliance with the
requirements of the SRI (Ecuador) for electronic invoicing. It allows signing
invoices, credit notes, withholding vouchers, and other tax documents. Updated
to SRI specification v2.31.

## Requirements

* Python >= 3.10
* Dependencies: `cryptography>=45.0.6`, `lxml>=5.4.0`

## Installation

* From PyPI:

  ```bash
  pip install sri-xades-signer
  ```

* From the repository:

  ```bash
  pip install git+https://github.com/Juanja1306/SRI-Xades-Signer.git
  ```

* Local:

  ```bash
  pip install -e .
  ```

## Quick usage

* One-time signing with `sign_xml` using a .p12 file:

  ```python
  from sri_xades_signer import sign_xml

  xml_text = open("comprobante.xml", "r", encoding="utf-8").read()
  xml_signed = sign_xml(
      pkcs12_file="path/to/certificate.p12",
      password="p12_password",
      xml=xml_text,
      read_file=True,  # indicates pkcs12_file is a file path
  )
  open("comprobante_signed.xml", "w", encoding="utf-8").write(xml_signed)
  ```

* Reusable with `XadesSigner` to sign multiple XMLs:

  ```python
  from sri_xades_signer import XadesSigner

  signer = XadesSigner(
      pkcs12_file="path/to/certificate.p12",
      password="p12_password",
      read_file=True,
  )
  xml_signed = signer.sign(xml_text)
  ```

* Sign and save in one step:

  ```python
  from sri_xades_signer import sign_and_save

  sign_and_save(
      pkcs12_file="path/to/certificate.p12",
      password="p12_password",
      xml_file="comprobante.xml",
      output_xml="comprobante_signed.xml",
  )
  ```

## Main API

* `sign_xml(pkcs12_file, password, xml, read_file=False) -> str`
* `XadesSigner(pkcs12_file, password, read_file=False).sign(xml) -> str`
* `sign_and_save(pkcs12_file, password, xml_file, output_xml) -> bool`
* Exception: `SignatureError`

## Important notes

* The root element of the document must have the attribute `Id="comprobante"`,
  since the signature reference points to `#comprobante`.
* Signature algorithm: RSA-SHA1 with exclusive canonicalization (exc-c14n),
  according to SRI requirements.

## Links

* Repository: [GitHub](https://github.com/Juanja1306/SRI-Xades-Signer)
* Issues: [GitHub Issues](https://github.com/Juanja1306/SRI-Xades-Signer/issues)

## License

Licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.  
See [`LICENSE`](./LICENSE)

## Provenance & Attribution

This project, **SRI-Xades-Signer**, is a derivative work of **jsonfm/xades-bes-sri**  
<https://github.com/jsonfm/xades-bes-sri> (AGPL-3.0).  
The upstream project itself credits **xades-bes-sri-ec** by @alfredo138923.

### Modifications by Juan Malo (2025-09-02)

- Package name and module structure: `sri_xades_signer` (pyproject-based).
- Public API additions:
  - `XadesSigner` class for re-usable signing.
  - `sign_and_save(...)` convenience function.
  - `SignatureError` for consistent error handling.
- Input ergonomics: support for PKCS#12 via file path using `read_file=True`.
- Documentation: updated examples and guidance for SRI spec **v2.31**.
- Dependency and packaging updates.

### Network Use Notice (AGPL-3.0 §13)

If this software (modified or not) is run as a network-accessible service, users of that service must be offered the **complete corresponding source code** of the exact version running, at no charge. A simple way is to expose a “Source” link pointing to this repository.

### Credits & Copyright

- Original work: **jsonfm/xades-bes-sri** — © jsonfm and contributors   
- Derivative work: **SRI-Xades-Signer** — © 2025 Juan Malo
from typing import Union, Optional
import re
from io import BufferedReader
from datetime import datetime
import base64
import hashlib
from lxml import etree
import xml.etree.ElementTree as ET
import codecs
import random
from pathlib import Path


# crypto
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


MAX_LINE_SIZE = 76
XML_NAMESPACES = 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:etsi="http://uri.etsi.org/01903/v1.3.2#"'

__all__ = [
    'sign_xml',
    'XadesSigner',
    'SignatureError',
    'sign_and_save'
]


class SignatureError(Exception):
    """Error en el proceso de firma XAdES-BES."""
    pass

def random_integer() -> int:
    """
    Generates a random integer between 990 and 999,989 (inclusive).

    Returns:
        int: A random integer.
    """
    return random.randint(990, 999989)

def format_xml_string(xml_string: str) -> str:
    """
    Format an XML string by removing unnecessary whitespace.

    Args:
        xml_string (str): The XML string to be formatted.

    Returns:
        str: The formatted XML string with unnecessary whitespace removed.
    """
    xml_string = xml_string.replace('\n', '')
    xml_string = re.sub(' +', ' ', xml_string).replace('> ', '>').replace(' <', '<')
    return xml_string

def get_key_info(certificate_x509: str, modulus: str, exponent: str) -> str:
    """
    Returns the <ds:KeyInfo> block with fixed ID "Certificate".
    """
    return f"""
    <ds:KeyInfo {XML_NAMESPACES} Id="Certificate">
        <ds:X509Data>
            <ds:X509Certificate>{certificate_x509}</ds:X509Certificate>
        </ds:X509Data>
        <ds:KeyValue>
            <ds:RSAKeyValue>
                <ds:Modulus>{modulus}</ds:Modulus>
                <ds:Exponent>{exponent}</ds:Exponent>
            </ds:RSAKeyValue>
        </ds:KeyValue>
    </ds:KeyInfo>
    """

def get_signed_properties(
    certificate_x509_der_hash: str,
    x509_serial_number: Union[int, str],
    reference_id_number: int,
    issuer_name: str
) -> str:
    signing_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    signed_properties = f"""
        <etsi:SignedProperties Id="SignedProperties">
        <etsi:SignedSignatureProperties>
            <etsi:SigningTime>{signing_time}</etsi:SigningTime>
            <etsi:SigningCertificate>
            <etsi:Cert>
                <etsi:CertDigest>
                <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                <ds:DigestValue>{certificate_x509_der_hash}</ds:DigestValue>
                </etsi:CertDigest>
                <etsi:IssuerSerial>
                <ds:X509IssuerName>{issuer_name}</ds:X509IssuerName>
                <ds:X509SerialNumber>{str(x509_serial_number)}</ds:X509SerialNumber>
                </etsi:IssuerSerial>
            </etsi:Cert>
            </etsi:SigningCertificate>
        </etsi:SignedSignatureProperties>
        <etsi:SignedDataObjectProperties>
            <etsi:DataObjectFormat ObjectReference="#Reference-ID-{reference_id_number}">
            <etsi:Description>contenido comprobante</etsi:Description>
            <etsi:MimeType>text/xml</etsi:MimeType>
            </etsi:DataObjectFormat>
        </etsi:SignedDataObjectProperties>
        </etsi:SignedProperties>
    """
    return format_xml_string(signed_properties)

def get_signed_info(
    signed_info_number: int,
    signed_properties_id_number: int,
    sha1_signed_properties: str,
    sha1_certificado: str,
    reference_id_number: int,
    sha1_comprobante: str
) -> str:
    return f"""
        <ds:SignedInfo Id="Signature-SignedInfo{signed_info_number}">
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>

        <!-- SignedProperties -->
        <ds:Reference Id="SignedPropertiesID{signed_properties_id_number}"
                        Type="http://uri.etsi.org/01903#SignedProperties"
                        URI="#SignedProperties">
            <ds:Transforms>
                <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            </ds:Transforms>
            <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
            <ds:DigestValue>{sha1_signed_properties}</ds:DigestValue>
        </ds:Reference>

        <!-- KeyInfo (#Certificate) -->
        <ds:Reference URI="#Certificate">
            <ds:Transforms>
                <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            </ds:Transforms>
            <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
            <ds:DigestValue>{sha1_certificado}</ds:DigestValue>
        </ds:Reference>

        <!-- Documento (enveloped + c14n) -->
        <ds:Reference Id="Reference-ID-{reference_id_number}" URI="#comprobante">
            <ds:Transforms>
                <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            </ds:Transforms>
            <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
            <ds:DigestValue>{sha1_comprobante}</ds:DigestValue>
        </ds:Reference>
        </ds:SignedInfo>
    """
    return signed_info

def get_xades_bes(
    xmls: str, 
    signature_number: int, 
    object_number: int, 
    signed_info: str, 
    signature: str, 
    key_info: str, 
    signed_properties: str
) -> str:
    """
    Generate XAdES-BES XML signature.

    Args:
        xmls (str): XML namespace declarations.
        signature_number (int): Number to identify the signature.
        signature_value_number (int): Number to identify the signature value.
        object_number (int): Number to identify the object.
        signed_info (str): Signed information.
        signature (str): Signature value.
        key_info (str): Key information.
        signed_properties (str): Signed properties.

    Returns:
        str: The generated XAdES-BES XML signature string.
    """
    xades_bes = f"""
    <ds:Signature {xmls} Id="Signature{signature_number}">
        {signed_info}
        <ds:SignatureValue>
            {signature}
        </ds:SignatureValue>
        {key_info}
        <ds:Object Id="Signature{signature_number}-Object{object_number}">
            <etsi:QualifyingProperties Target="#Signature{signature_number}">
                {signed_properties}
            </etsi:QualifyingProperties>
        </ds:Object>
    </ds:Signature>
"""

    return xades_bes

def sha1_base64(text: Union[str, bytes]) -> str:
    """
    Returns the SHA1 hash of the input text encoded in base64.

    Args:
        text (Union[str, bytes]): The input text.

    Returns:
        str: The SHA1 hash encoded in base64.
    """
    m = hashlib.sha1()
    if isinstance(text, str):
        text = text.encode()
    m.update(text)
    sha1_hex = m.digest()
    b64 = encode_base64(sha1_hex)
    return b64

def sha1(text: Union[str, bytes]) -> str:
    """
    Returns the SHA1 hash of the input text.

    Args:
        text (Union[str, bytes]): The input text.

    Returns:
        str: The SHA1 hash.
    """
    m = hashlib.sha1()
    if isinstance(text, str):
        text = text.encode()
    m.update(text)
    return m.hexdigest()

def split_string_every_n(string: str, n: int) -> str:
    """
    Splits a string every n characters.

    Args:
        string (str): The input string.
        n (int): The number of characters to split.

    Returns:
        str: The string with every n characters separated by a newline.
    """
    result = [string[i:i + n] for i in range(0, len(string), n)]
    return '\n'.join(result)

def _append_signature_fragment(xml_text: str, signature_fragment: str) -> str:
    """
    Append a signature XML fragment as the last child of the document root,
    preserving (if present) the original XML declaration.

    Args:
        xml_text: Original XML document as string.
        signature_fragment: A well-formed XML fragment (e.g., <ds:Signature ...>...)</n+            which includes its necessary namespace declarations.

    Returns:
        The XML with the signature appended as last child of the root element.
    """
    # Capture optional XML declaration
    decl_match = re.match(r"^\s*(<\?xml[^>]*\?>)\s*", xml_text)
    xml_decl: Optional[str] = decl_match.group(1) if decl_match else None

    # Parse original document (handle optional declaration)
    xml_source = xml_text.encode('utf-8')
    if xml_text.lstrip().startswith('<?xml'):
        # keep original declaration for re-prepend, but parse as bytes directly
        root = etree.fromstring(xml_source)
    else:
        root = etree.fromstring(xml_source)
    sig_el = etree.fromstring(signature_fragment.encode('utf-8'))
    root.append(sig_el)
    # Serialize without declaration; re-prepend if it existed
    serialized = etree.tostring(root, encoding='utf-8', xml_declaration=False).decode('utf-8')
    if xml_decl:
        # Ensure a single newline between declaration and root if original had one
        sep = "\n" if xml_text.lstrip().startswith(xml_decl + "\n") else ""
        return f"{xml_decl}{sep}{serialized}"
    return serialized

def encode_base64(data: Union[str, bytes], encoding: str = 'UTF-8') -> str:
    """
    Encodes a string or bytes to base64.

    Args:
        data (Union[str, bytes]): The input string or bytes.
        encoding (str, optional): The encoding. Defaults to 'UTF-8'.

    Returns:
        str: The base64 encoded string.
    """
    if isinstance(data, str):
        data = data.encode(encoding)
    return base64.b64encode(data).decode('ascii')

def get_xml_end_node(xml_tree: ET.ElementTree) -> str:
    """
    Returns the closing tag for the root node of an XML ElementTree.

    Args:
        xml_tree (ET.ElementTree): The XML ElementTree.

    Returns:
        str: The closing tag for the root node.
    """
    return f"</{xml_tree.getroot().tag}>"

def canonicalize_lxml(xml_string: Union[str, bytes]) -> str:
    """
    Performs Canonicalization (c14n) on the provided XML string using lxml.

    Args:
        xml_string (str): The XML string to be canonicalized.

    Returns:
        str: The canonicalized XML as a UTF-8 string.
    """
    # Lxml not accept Unicode with encoding declaration; handle both cases
    if isinstance(xml_string, bytes):
        parsed = etree.fromstring(xml_string)
    else:
        # Remove declaration if it exists to avoid lxml error
        xml_string = re.sub(r'^\s*<\?xml[^>]*\?>\s*', '', xml_string)
        parsed = etree.fromstring(xml_string.encode('utf-8'))

    # Perform canonicalization
    canonical_xml: bytes = etree.tostring(parsed, method="c14n", exclusive=True, with_comments=False)
    return canonical_xml.decode("utf-8")

def get_exponent(exp_int: int) -> str:
    """
    Converts an integer exponent to a base64 string.

    Args:
        exp_int (int): The integer exponent.

    Returns:
        str: The base64 string representation of the exponent.
    """
    hex_exp = '{:X}'.format(exp_int)
    # Ensure even number of hex digits (full bytes)
    if len(hex_exp) % 2 != 0:
        hex_exp = '0' + hex_exp
    # Pad to at least 3 bytes as historically expected by some consumers
    hex_exp = hex_exp.zfill(6)
    decoded_hex = codecs.decode(hex_exp, 'hex')
    base64_exp = codecs.encode(decoded_hex, 'base64').decode().strip()
    return base64_exp

def get_modulus(modulus_int: int, max_line_size: int = 76) -> str:
    """
    Converts an integer modulus to base64-encoded string and splits it into lines.

    Args:
        modulus_int (int): The integer modulus.
        max_line_size (int): The maximum line size for splitting.

    Returns:
        str: The base64-encoded modulus split into lines.
    """
    # Convert integer modulus to hexadecimal string
    modulus_hex = '{:X}'.format(modulus_int)
    # Ensure even number of hex digits
    if len(modulus_hex) % 2 != 0:
        modulus_hex = '0' + modulus_hex
    modulus_bytes = bytes.fromhex(modulus_hex)

    # Encode bytes to base64
    modulus_base64 = base64.b64encode(modulus_bytes).decode('latin-1')

    # Split base64-encoded modulus into lines
    modulus_split = '\n'.join([modulus_base64[i:i+max_line_size] for i in range(0, len(modulus_base64), max_line_size)])

    return modulus_split

def get_x509_certificate(certificate_pem: str, max_line_size: int = MAX_LINE_SIZE) -> str:
    """
    Extracts X.509 certificate from PEM-encoded string and splits it into lines.

    Args:
        certificate_pem (str): The PEM-encoded certificate string.
        max_line_size (int): The maximum line size for splitting.

    Returns:
        str: The X.509 certificate split into lines.
    """
    # Find X.509 certificate between "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----"
    certificate_regex = r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----"
    certificate_match = re.search(certificate_regex, certificate_pem, flags=re.DOTALL)

    if not certificate_match:
        return ''
    certificate_x509 = certificate_match.group(1)
    certificate_x509 = re.sub(r"\s+", "", certificate_x509)
    return '\n'.join([certificate_x509[i:i+max_line_size] for i in range(0, len(certificate_x509), max_line_size)])

def get_private_key(file: Union[str, bytes, BufferedReader], password: Union[str, bytes], read_file: bool = False):
    """
    Retrieves the private key from a PKCS#12 file.

    Args:
        file (Union[str, bytes, BufferedReader]): The path to the PKCS#12 file,
            or the PKCS#12 file content as bytes, or a BufferedReader object.
        password (Union[str, bytes]): The password to decrypt the PKCS#12 file.
        read_file (bool, optional): If True and `file` is a string representing a file path,
            the function will read the file content. Defaults to False.

    Returns:
        object: PKCS#12 container (key, cert, and additional certs) as returned by cryptography.
    """

    if isinstance(file, str):
        if read_file:
            with open(file, 'rb') as p12_file:
                data = p12_file.read()
        else:
            data = file.encode("utf-8")

    if isinstance(file, bytes):
        data = file
        
    if isinstance(file, BufferedReader):
        data = file.read()
    
    if isinstance(password, str):
        password = password.encode()
    
    keys = pkcs12.load_pkcs12(data, password)

    return keys

def parse_issuer_name(issuer):
    """
    Returns the complete DN in the RFC 2253 order that the SRI expects.
    """
    # Collect values regardless of RDN order, then output in required order
    dn_values = {}
    for rdn in issuer.rdns:
        for av in rdn:
            oid = av.oid
            value = str(av.value).replace(',', '\\,')
            if oid == NameOID.COUNTRY_NAME:
                dn_values['C'] = value
            elif oid == NameOID.ORGANIZATION_NAME:
                dn_values['O'] = value
            elif oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                dn_values['OU'] = value
            elif oid == NameOID.COMMON_NAME:
                dn_values['CN'] = value
    ordered = []
    for key in ('C', 'O', 'OU', 'CN'):
        if key in dn_values:
            ordered.append(f"{key}={dn_values[key]}")
    return ",".join(ordered)

def sign_xml(
    pkcs12_file: Union[str, bytes], 
    password: Union[str, bytes], 
    xml: Union[str, bytes], 
    read_file: bool = False
) -> str:
    """
    Processes and signs an XML document (with or without XML declaration).

    Args:
        pkcs12_file (Union[str, bytes]): The path to the PKCS12 file or the content of the file.
        password (Union[str, bytes]): The password to decrypt the PKCS12 file.
        xml (Union[str, bytes]): The XML document to sign. If bytes, assumed UTF-8.
        read_file (bool, optional): Whether to read the PKCS12 file as a binary file. Defaults to False.

    Returns:
        str: The signed XML document.
    """
    
    if isinstance(xml, bytes):
        xml = xml.decode('utf-8')
    if not isinstance(xml, str) or not xml.strip():
        raise ValueError("The XML to sign must be a non-empty string or bytes.")

    if isinstance(password, str):
        password = password.encode("utf-8")

    try:
        keys = get_private_key(pkcs12_file, password, read_file=read_file)
    except Exception as exc:
        raise SignatureError(f"No se pudo cargar el PKCS#12: {exc}") from exc
    try:
        certificate_der = keys.cert.certificate.public_bytes(encoding=serialization.Encoding.DER)
        certificate_pem = keys.cert.certificate.public_bytes(encoding=serialization.Encoding.PEM)
    except Exception as exc:
        raise SignatureError(f"No se pudo extraer el certificado del PKCS#12: {exc}") from exc

    certificate_x509 = get_x509_certificate(certificate_pem.decode("utf-8"))
    certificate_x509_der_hash = sha1_base64(certificate_der)

    public_key_numbers = keys.cert.certificate.public_key().public_numbers()
    modulus = get_modulus(public_key_numbers.n)
    exponent = get_exponent(public_key_numbers.e)

    serial_number = keys.cert.certificate.serial_number
    issuer_name = parse_issuer_name(keys.cert.certificate.issuer)

    xml_c14n = canonicalize_lxml(xml)             # exc-c14n of the document (the root is #comprobante)
    sha1_invoice = sha1_base64(xml_c14n.encode())


    signature_number = random_integer()

    signed_info_number = random_integer()
    signed_properties_id_number = random_integer()
    reference_id_number = random_integer()
    signature_value_number = random_integer()

    signed_properties = get_signed_properties(
        certificate_x509_der_hash,  # hash SHA-1 of the DER certificate
        serial_number,              # X.509 serial number
        reference_id_number,        # random id of Reference
        issuer_name                 # complete DN C,O,OU,CN
    )

    signed_props_ns = signed_properties.replace(
        "<etsi:SignedProperties",
        f"<etsi:SignedProperties {XML_NAMESPACES}",
        1,
    )
    sha1_signed_properties = sha1_base64(
        canonicalize_lxml(signed_props_ns).encode()
    )

    key_info = get_key_info(
        certificate_x509, 
        modulus, 
        exponent
    )

    key_info_c14n    = canonicalize_lxml(key_info)
    sha1_certificate = sha1_base64(key_info_c14n.encode('UTF-8'))

    signed_info = get_signed_info(
        signed_info_number,
        signed_properties_id_number,
        sha1_signed_properties,
        sha1_certificate,
        reference_id_number,
        sha1_invoice
    )

    signed_info_for_signature = signed_info.replace('<ds:SignedInfo', '<ds:SignedInfo ' + XML_NAMESPACES)

    signed_info_for_signature = canonicalize_lxml(signed_info_for_signature)

    try:
        signature = keys.key.sign(signed_info_for_signature.encode("utf-8"), padding.PKCS1v15(), SHA1())
    except Exception as exc:
        raise SignatureError(f"No se pudo generar la firma PKCS#1 v1.5: {exc}") from exc

    signature = encode_base64(signature)

    signature = split_string_every_n(signature, MAX_LINE_SIZE)

    xades_bes = get_xades_bes(
        xmls=XML_NAMESPACES, 
        signature_number=signature_number, 
        object_number=signature_value_number, 
        signed_info=signed_info, 
        signature=signature, 
        key_info=key_info,
        signed_properties=signed_props_ns
    )

    try:
        signed_xml = _append_signature_fragment(xml, xades_bes)
    except Exception as exc:
        raise SignatureError(f"No se pudo insertar la firma en el XML: {exc}") from exc

    return signed_xml

class XadesSigner:
    """
    Reusable XAdES-BES signer.
    Load the PKCS#12 once and sign multiple XML:

        signer = XadesSigner(pkcs12_bytes, password)
        xml_firmado = signer.sign(xml_str)
    """

    # ---------------  init ---------------
    def __init__(
        self,
        pkcs12_file: Union[str, bytes, BufferedReader],
        password: Union[str, bytes],
        read_file: bool = False,
    ):
        password_b = password.encode() if isinstance(password, str) else password
        try:
            self._keys = get_private_key(pkcs12_file, password_b, read_file=read_file)
        except Exception as e:
            raise SignatureError(f"No se pudo cargar el PKCS#12: {e}") from e

        # ----- fixed data that we will reuse in all signatures ----------
        cert = self._keys.cert.certificate
        self._cert_pem: bytes = cert.public_bytes(serialization.Encoding.PEM)
        self._cert_der: bytes = cert.public_bytes(serialization.Encoding.DER)
        self._cert_x509: str = get_x509_certificate(self._cert_pem.decode())
        self._cert_der_hash: str = sha1_base64(self._cert_der)

        pub_numbers = cert.public_key().public_numbers()
        self._modulus: str = get_modulus(pub_numbers.n)
        self._exponent: str = get_exponent(pub_numbers.e)
        self._serial_number = cert.serial_number
        self._issuer_name = parse_issuer_name(cert.issuer)

    # --------------- sign ---------------
    def sign(self, xml: Union[str, bytes]) -> str:
        if isinstance(xml, bytes):
            xml = xml.decode()
        if not isinstance(xml, str) or not xml.strip():
            raise ValueError("The XML to sign must be a non-empty string/bytes")

        # ---------- hash of the document (enveloped) -----------------------
        sha1_invoice = sha1_base64(canonicalize_lxml(xml).encode())

        # ---------- dynamic blocks ------------------------------------
        sig_id          = random_integer()
        info_id         = random_integer()
        props_id        = random_integer()
        ref_id          = random_integer()
        object_id       = random_integer()

        # ---------- SignedProperties --------------------------------------
        signed_props = get_signed_properties(
            self._cert_der_hash,
            self._serial_number,
            ref_id,
            self._issuer_name,
        )

        # Inject the xmlns inside the node before calculating the hash
        signed_props_ns = signed_props.replace(
            "<etsi:SignedProperties",
            f"<etsi:SignedProperties {XML_NAMESPACES}",
            1,
        )

        sha1_signed_props = sha1_base64(canonicalize_lxml(signed_props_ns).encode())

        # ---------- KeyInfo ------------------------------------------------
        key_info = get_key_info(self._cert_x509, self._modulus, self._exponent)
        sha1_cert = sha1_base64(canonicalize_lxml(key_info).encode())

        # ---------- SignedInfo (+ xmlns **already included**) -------------------
        signed_info = get_signed_info(
            info_id,
            props_id,
            sha1_signed_props,
            sha1_cert,
            ref_id,
            sha1_invoice,
        ).replace(
            "<ds:SignedInfo",
            f'<ds:SignedInfo {XML_NAMESPACES}',
            1,
        )
        signed_info_c14n = canonicalize_lxml(signed_info)

        # ---------- PKCS#1 v1.5 signature --------------------------------------
        try:
            sig_bytes = self._keys.key.sign(
                signed_info_c14n.encode(),
                padding.PKCS1v15(),
                SHA1(),
            )
        except Exception as e:
            raise SignatureError(f"No se pudo generar la firma: {e}") from e
        sig_b64 = split_string_every_n(encode_base64(sig_bytes), MAX_LINE_SIZE)

        # ---------- Complete XAdES-BES signature ---------------------------
        xades_bes = get_xades_bes(
            xmls=XML_NAMESPACES,
            signature_number=sig_id,
            object_number=object_id,
            signed_info=signed_info,
            signature=sig_b64,
            key_info=key_info,
            signed_properties=signed_props_ns,
        )

        # ---------- insert at the end of the original XML ---------------------
        try:
            return _append_signature_fragment(xml, xades_bes)
        except Exception as e:
            raise SignatureError(f"No se pudo insertar la firma: {e}") from e

def sign_and_save(pkcs12_file: str, 
                    password: str, 
                    output_xml: str, 
                    xml_file: str) -> bool:
    """
    Sign an XML document and save the signed XML to a file.
    """
    try:
        p12_bytes  = Path(pkcs12_file).read_bytes()
        
        xml_string = Path(xml_file).read_text(encoding="utf-8")

        signed_xml = sign_xml(
            pkcs12_file=p12_bytes,
            password=password.encode(),
            xml=xml_string
            )
        Path(output_xml).write_text(signed_xml, encoding="utf-8")
        return True
    except SignatureError as e:
        raise SignatureError(f"Error in signature: {e}") from e
    except Exception as e:
        raise SignatureError(f"Unexpected error: {e}") from e

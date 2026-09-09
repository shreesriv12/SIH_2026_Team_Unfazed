from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from core.analyzer import assess_certificate_chain, assess_certificate_trust, certificate_hostname_status


def make_certificate(subject: str, issuer: str, public_key, signer, issuer_key):
    return (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)])).public_key(public_key).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1)).not_valid_after(datetime.now(UTC) + timedelta(days=1)).sign(issuer_key, hashes.SHA256()))


def make_ca(subject: str, key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))


def test_certificate_chain_states_distinguish_leaf_only_and_verified_links():
    root_key, leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048), rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = make_certificate("root", "root", root_key.public_key(), root_key, root_key)
    leaf = make_certificate("mail", "root", leaf_key.public_key(), root, root_key)
    assert assess_certificate_chain([leaf]) == "LEAF_ONLY_CHAIN_INCOMPLETE"
    assert assess_certificate_chain([leaf, root]) == "CHAIN_LINKS_VERIFIED_TRUST_NOT_VALIDATED"


def test_trust_store_distinguishes_trusted_and_incomplete_paths():
    root_key, leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048), rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = make_ca("trusted-root", root_key)
    leaf = make_certificate("mail", "trusted-root", leaf_key.public_key(), root, root_key)
    assert assess_certificate_trust([leaf], [root]) == "TRUSTED"
    assert assess_certificate_trust([leaf], []) == "TRUST_STORE_NOT_CONFIGURED"


def test_unknown_issuer_is_an_incomplete_chain():
    root_key, leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048), rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = make_ca("unknown-root", root_key)
    leaf = make_certificate("mail", "unknown-root", leaf_key.public_key(), root, root_key)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert assess_certificate_trust([leaf], [make_ca("other-root", other_key)]) == "INCOMPLETE_CHAIN"


def test_certificate_hostname_matches_san_and_rejects_wrong_host():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unused.example")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1)).not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("mail.example.test"), x509.DNSName("*.mx.example.test")]), critical=False)
        .sign(key, hashes.SHA256()))
    assert certificate_hostname_status(cert, "mail.example.test") == "MATCHED"
    assert certificate_hostname_status(cert, "a.mx.example.test") == "MATCHED"
    assert certificate_hostname_status(cert, "a.b.mx.example.test") == "MISMATCH"
    assert certificate_hostname_status(cert, "wrong.example.test") == "MISMATCH"

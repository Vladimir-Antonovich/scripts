#!/usr/bin/env python

import argparse
import sys
import logging
import datetime
import ipaddress
from OpenSSL import crypto
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from ruamel.yaml import YAML


CACERT_FILE = 'cacert.pem'
CAKEY_FILE = 'cakey.pem'

logger = None


def logger():
    logger = logging.getLogger()
    logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] \
                                     [%(levelname)-5.5s]  %(message)s")
    consoleHandler = logging.StreamHandler(sys.stdout)
    consoleHandler.setFormatter(logFormatter)
    logger.addHandler(consoleHandler)
    logger.setLevel(logging.DEBUG)
    return logger


def generate_ca_cert(properties={}):
    logger.info("Generating ca certificate...")
    # _check_inputs(properties)

    parameters = {}
    parameters['commonname'] = u"{}".format(properties.get('commonname'))
    if properties.get('password') != '':
        parameters['password'] = properties.get('password')
    else:
        parameters['password'] = None
    cacert, cakey = _generate_ca_cert(parameters)
    cacert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cacert)
    cakey_pem = cakey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    # logger.info("CA certificate:\n{}".format(cacert_pem))
    # logger.info("CA key:\n{}".format(cakey_pem))
    return cacert_pem, cakey_pem


def issue_certificate(cacert, cakey, properties={}):
    logger.debug("Issuing certificate...")
    # _check_inputs(properties)

    cacert_pem = u"{}".format(cacert.decode("utf-8"))
    cakey_pem = u"{}".format(cakey.decode("utf-8"))

    cacert = x509.load_pem_x509_certificate(cacert_pem.encode("ascii"),
                                            default_backend())

    cakey = serialization.load_pem_private_key(cakey_pem.encode("ascii"),
                                               password=None,
                                               backend=default_backend())

    parameters = {}
    parameters['country'] = u"{}".format(properties.get('country'))
    parameters['state'] = u"{}".format(properties.get('state'))
    parameters['location'] = u"{}".format(properties.get('location'))
    parameters['organization'] = u"{}".format(properties.get('organization'))
    parameters['commonname'] = u"{}".format(properties.get('commonname'))
    parameters['commonname_ip'] = u"{}".format(properties.get('commonname_ip'))
    subjectaltname = properties.get('subjectaltname')

    subjectaltname_list = [
        x509.IPAddress(ipaddress.ip_address(u'{}'.format(
            parameters.get('commonname_ip')))),
        x509.DNSName(u"{}".format(
            parameters.get('commonname_ip'))),
        x509.DNSName(u"{}".format(
            parameters.get('commonname'))),
        x509.IPAddress(ipaddress.ip_address(u'127.0.0.1')),
        x509.DNSName(u"{localhost_dns}".format(localhost_dns="127.0.0.1")),
        x509.DNSName(u"{localhost_dns}".format(localhost_dns="localhost")),

    ]

    for param in subjectaltname.get('ips'):
        if not param:
            continue
        try:
            ip_address = ipaddress.ip_address(u'{}'.format(
                    param))
        except ValueError:
            continue
        subjectaltname_list.append(
            x509.IPAddress(ip_address)
        )
    for param in subjectaltname.get('ips'):
        if not param:
            continue
        subjectaltname_list.append(
            x509.DNSName(u"{}".format(
                param))
        )
    for param in subjectaltname.get('names'):
        if not param:
            continue
        subjectaltname_list.append(
            x509.DNSName(u"{}".format(
                param))
        )

    logger.debug("{}".format(subjectaltname_list))
    parameters['subjectaltname'] = subjectaltname_list

    cert, key = _issue_certificate(cacert, cakey, parameters)
    cert_pem = crypto.dump_certificate(
        crypto.FILETYPE_PEM, cert)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return cert_pem, key_pem


def _generate_ca_cert(params):
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"{}".format(
            params.get('commonname'))),
    ])

    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(
            ca_key.public_key()),
        critical=False
    ).sign(private_key=ca_key, algorithm=hashes.SHA256(),
           backend=default_backend())
    return ca_cert, ca_key


def _issue_certificate(cacert, cakey, params):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, params.get('commonname')),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        cacert.subject
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        extension=x509.KeyUsage(
            digital_signature=True, key_encipherment=True,
            content_commitment=True, data_encipherment=False,
            key_agreement=False, encipher_only=False,
            decipher_only=False, key_cert_sign=False, crl_sign=True
        ),
        critical=True
    ).add_extension(
        x509.SubjectAlternativeName(params.get('subjectaltname')),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=False
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(
            key.public_key()),
        critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            cakey.public_key()),
        critical=False
    ).sign(cakey, hashes.SHA256(), default_backend())

    return cert, key


def _check_inputs(test_dict):
    for key in test_dict:
        if test_dict.get(key) == "":
            logger.info("Key '{}' is empty".format(key))
            raise


def main():

    global logger
    logger = logger()
    parser = argparse.ArgumentParser()
    parser.add_argument('--create-ca', action="store_true",
                        help='Generate new CA certificate.')

    parser.add_argument('--cacert-path', type=str, default='',
                        help='Filepath to CA certificate. \
                            CA cert will be save to that path if new-ca set.')

    parser.add_argument('--cakey-path', type=str, default='',
                        help='Filepath to CA key. \
                            CA key will be save to that path if new-ca set.')

    parser.add_argument('--issue_certificates', action="store_true",
                        help='Create and sign new certificates for CM')

    parser.add_argument('--parameters', '-p', type=str, default='',
                        help='yaml file with certificates parameters')

    parser.add_argument('--save-path', '-d', type=str, default='',
                        help='yaml file with certificates parameters')

    args = parser.parse_args()
    logger.debug(args)

    cacert = None
    cakey = None
    save_path = './'
    yaml = YAML()

    if args.save_path:
        save_path = args.save_path

    if args.create_ca:
        with open(args.parameters, 'r') as f:
            properties = yaml.load(f)
        logger.info(properties)
        cacert, cakey = generate_ca_cert(properties.get("ca"))
        with open(save_path + '/' + CACERT_FILE, 'wb') as f:
            f.write(cacert)

        with open(save_path + '/' + CAKEY_FILE, 'wb') as f:
            f.write(cakey)

    if args.cacert_path:
        with open(args.cacert_path, 'rb') as f:
            cacert = f.read()

    if args.cakey_path:
        with open(args.cakey_path, 'rb') as f:
            cakey = f.read()

    if args.issue_certificates:
        with open(args.parameters, 'r') as f:
            properties = yaml.load(f)
        for n in properties.get('certificates'):
            cert_pem, key_pem = issue_certificate(cacert, cakey, n)
            with open(save_path + '/' + n.get('commonname') +
                      '_cert.pem', 'wb') as f:
                f.write(cert_pem)

            with open(save_path + '/' + n.get('commonname') +
                      '_key.pem', 'wb') as f:
                f.write(key_pem)


if __name__ == '__main__':
    main()

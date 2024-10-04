import os
import OpenSSL

import certmitm.util


class certtest(object):
    def __init__(self, name, hostname, certfile, keyfile, original_cert_pem):
        self.name = name
        self.hostname = hostname
        self.certfile = certfile
        self.keyfile = keyfile
        ctx = certmitm.util.create_server_context()
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self.context = ctx
        self.original_cert = original_cert_pem
        self.mitm = False

    def to_str(self):
        return f"Name: {self.name}, hostname: {self.hostname}, cert: {self.certfile} + {self.keyfile}"


def generate_test_context(original_cert_chain_pem, hostname, working_dir, logger):
    if not original_cert_chain_pem:
        logger.info(f"No cert chain to generate certificates for {hostname}, making up one.")
        gen_cert, gen_key = certmitm.util.generate_certificate(cn=hostname)
        original_cert_chain_pem = [OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, gen_cert)]

    # Self-signed
    tmp_cert_chain = []
    for tmp_cert_pem in original_cert_chain_pem:
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, tmp_cert_pem)
        tmp_cert_chain.append(cert)
    name = "self_signed"
    tmp_cert_chain[0].set_issuer(tmp_cert_chain[0].get_subject())
    tmp_cert_chain[0], key = certmitm.util.sign_certificate(tmp_cert_chain[0], issuer_cert=None)
    certfile, keyfile = certmitm.util.save_certificate_chain([tmp_cert_chain[0]], key, working_dir, name=f"{hostname}_{name}")
    yield certtest(name, hostname, certfile, keyfile, original_cert_chain_pem)

    # Replaced key
    tmp_cert_chain = []
    for tmp_cert_pem in original_cert_chain_pem:
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, tmp_cert_pem)
        tmp_cert_chain.append(cert)
    name = "replaced_key"
    tmp_cert_chain[0], key = certmitm.util.replace_public_key(tmp_cert_chain[0])
    certfile, keyfile = certmitm.util.save_certificate_chain(tmp_cert_chain, key, working_dir, name=f"{hostname}_{name}")
    yield certtest(name, hostname, certfile, keyfile, original_cert_chain_pem)

    # Real certs
    real_certs = list(filter(None, [file if "_cert.pem" in file else None for file in os.listdir("real_certs")]))
    for cert in real_certs:
        basename = cert.split("_cert.pem")[0]
        certfile = "real_certs/{}_cert.pem".format(basename)
        keyfile = "real_certs/{}_key.pem".format(basename)
        name = f'real_cert_{basename}'

        # Real cert as is
        yield certtest(name, hostname, certfile, keyfile, original_cert_chain_pem)

        # Real cert as CA
        real_cert_chain_pem = []
        with open(certfile) as certf:
            certcontent = certf.read()
        buffer = ""
        for i in certcontent.split("\n"):
            if "CERTIFICATE" in i:
                if buffer:
                    buffer = f"-----BEGIN CERTIFICATE-----\n{buffer}-----END CERTIFICATE-----\n"
                    real_cert_chain_pem.append(buffer)
                    buffer = ""
            else:
                buffer += f"{i}\n"

        real_cert_chain = []
        for real_cert_pem in real_cert_chain_pem:
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, real_cert_pem)
            real_cert_chain.append(cert)

        with open(keyfile) as keyf:
            real_cert_chain_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, keyf.read())

        orig_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, original_cert_chain_pem[0])

        tmp_cert_chain = []
        tmp_cert_chain.append(orig_cert)
        tmp_cert_chain.extend(real_cert_chain)

        cert, key = certmitm.util.sign_certificate(tmp_cert_chain[0], key=None, issuer_cert=tmp_cert_chain[1], issuer_key=real_cert_chain_key)
        tmp_cert_chain[0] = cert

        name = f"real_cert_CA_{basename}"

        certfile, keyfile = certmitm.util.save_certificate_chain(tmp_cert_chain, key, working_dir, name=f"{hostname}_{name}")
        yield certtest(name, hostname, certfile, keyfile, original_cert_chain_pem)

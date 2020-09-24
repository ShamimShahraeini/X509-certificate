import sys
import os
import ssl
import pprint
import OpenSSL
from cryptography.hazmat.backends import default_backend

def read_validate_cert(root_crt, intermediate_cert, validate_crt):

    try:
        root_cert_dict = ssl._ssl._test_decode_cert(os.path.join(os.path.dirname(__file__), root_crt))
        validate_cert_dict = ssl._ssl._test_decode_cert(os.path.join(os.path.dirname(__file__), validate_crt))
    except Exception as e:
        print("Error decoding certificate: {0:}".format(e))
    else:
        # print("Certificate ({0:s}) data:\n".format(root_crt))
        # pprint.pprint(root_cert_dict)
        print("Certificate ({0:s}) data:\n".format(validate_crt))
        pprint.pprint(validate_cert_dict)
        # print(root_cert_dict['notAfter'])
        print(100*"_")

    try:
        certx509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, open(validate_crt, 'rt').read())
    except Exception as e:
        raise Exception("Failed to load certstring")

    trusted_certs = OpenSSL.crypto.X509Store()
    if intermediate_cert != None:
        incert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, open(intermediate_cert, 'rt').read())
        trusted_certs.add_cert(incert)
        cacert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, open(root_crt, 'rt').read())
        trusted_certs.add_cert(cacert)
    
    if intermediate_cert == None:
        for trusted_cert_pem in open(root_crt, 'rt').read():
            trusted_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, trusted_cert_pem)
            store.add_cert(trusted_cert)


    try:
        store_ctx = OpenSSL.crypto.X509StoreContext(trusted_certs, certx509)
    except X509StoreContextError as exp:
        cert = exp.certificate
        print('X509StoreContextError:{}\ncertificate\n\tissuer :{}\n\tsubject:{}'.
            format(exp.args, cert.get_issuer(), cert.get_subject()))
    # Verify the certificate. Raises X509StoreContextError on error.
    try:
        store_ctx.verify_certificate()
        print("certificate verified :)")
    except Exception as e:
        print("Failed to verify certificate: %s" % e)


read_validate_cert("root.org.crt", "middle7.org.crt", "leaf15.org.crt")
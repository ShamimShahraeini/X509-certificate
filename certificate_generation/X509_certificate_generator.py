
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_cert():

    # Generate our key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Write our key to disk for safe keeping
    # with open("key.pem", "wb") as f:
    #     f.write(key.private_bytes(
    #        encoding=serialization.Encoding.PEM,
    #        format=serialization.PrivateFormat.TraditionalOpenSSL,
    #        encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
    #     ))

    # Generate a CSR
    print("How would you like to generate csr data?\n" \
        "1) Default.\n" \
        "2) Specify your own.\n" )
    option = input("Choose (1/2): ")
    
    if option == "1":
        c = "US"
        st = "California"
        l = "San Francisco"
        o = "My Company"
        ou = "mysite.com"
        dn = "www.mysite.com"
        
    elif option == "2":
        c = input("Enter your country(ex. US): ")
        st = input("Enter your state(ex. Nevada): ")
        l = input("Enter your location(City): ")
        o = input("Enter your organization: ")
        ou = input("Enter your organizational unit(ex. IT): ")
        dn = input("Enter your sites you want this certificate for(ex. mysite.com): ")
        
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, c),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, st),
        x509.NameAttribute(NameOID.LOCALITY_NAME, l),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, o),
        x509.NameAttribute(NameOID.COMMON_NAME, ou),
    ])).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName(dn),
        ]),
        critical=False,
        # Sign the CSR with our private key.
    ).sign(key, hashes.SHA256(), default_backend())
    # Test
    # Write our CSR out to disk.
    # with open("csr.pem", "wb") as f:
    #     f.write(csr.public_bytes(serialization.Encoding.PEM))

    return csr.public_bytes(serialization.Encoding.PEM)


my_csr = generate_cert()
# print(my_csr)
with open("UnsignedCertificate.csr", "wb") as f:
    f.write(my_csr)
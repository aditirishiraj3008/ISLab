"""HealthCare Inc., a leading healthcare provider, has implemented a secure patient data
management system using the Rabin cryptosystem. The system allows authorized
healthcare professionals to securely access and manage patient records across multiple
hospitals and clinics within the organization. Implement a Python-based centralized key
management service that can:
• Key Generation: Generate public and private key pairs for each hospital and clinic
using the Rabin cryptosystem. The key size should be configurable (e.g., 1024 bits).
• Key Distribution: Provide a secure API for hospitals and clinics to request and receive
their public and private key pairs.
• Key Revocation: Implement a process to revoke and update the keys of a hospital or
clinic when necessary (e.g., when a facility is closed or compromised).
• Key Renewal: Automatically renew the keys of all hospitals and clinics at regular
intervals (e.g., every 12 months) to maintain the security of the patient data management
system.
• Secure Storage: Securely store the private keys of all hospitals and clinics, ensuring
that they are not accessible to unauthorized parties.
• Auditing and Logging: Maintain detailed logs of all key management operations, such
as key generation, distribution, revocation, and renewal, to enable auditing and
compliance reporting.
• Regulatory Compliance: Ensure that the key management service and its operations are compliant with relevant data privacy regulations (e.g., HIPAA).
• Perform a trade-off analysis to compare the workings of Rabin and RSA."""

import secrets, logging
from sympy import isprime
from sympy.ntheory.generate import randprime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

class RabinKMS:
    def __init__(self, bits=1024):
        self.bits = bits
        self.keys = {}
        self.revoked = set()

    def gen_blum_prime(self, b):
        while True:
            p = randprime(2**(b-1), 2**b)
            if p % 4 == 3 and isprime(p):
                return p

    def gen_keys(self, name):
        b = self.bits // 2
        p, q = self.gen_blum_prime(b), self.gen_blum_prime(b)
        self.keys[name] = (p, q, p*q)
        logging.info(f"Keys generated for {name}")
        return self.keys[name]

    def get_pubkey(self, name):
        if name in self.revoked:
            logging.warning(f"Key for {name} revoked")
            return None
        return self.keys.get(name, (None, None, None))[2]

    def revoke(self, name):
        self.revoked.add(name)
        logging.info(f"Key revoked for {name}")

    def renew_all(self):
        logging.info("Renewing all keys")
        for name in [k for k in self.keys if k not in self.revoked]:
            self.gen_keys(name)
        logging.info("Renewal done")

if __name__=="__main__":
    kms = RabinKMS()
    kms.gen_keys("Hospital A")
    kms.gen_keys("Clinic B")
    print("Hospital A Public Key:", kms.get_pubkey("Hospital A"))
    kms.revoke("Clinic B")
    kms.renew_all()

    print("\nTrade-off Rabin vs RSA:")
    print("- Rabin: faster encryption, decryption has 4 solutions, less common.")
    print("- RSA: widely used, slower encryption, simpler decryption.")
    print("- Both rely on factoring; key sizes similar for security.")

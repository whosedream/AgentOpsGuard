from cryptography.fernet import Fernet


class CredentialVault:
    """Encrypt outbound credentials with an API-process-only master key."""

    def __init__(self, key: str) -> None:
        self._fernet = Fernet(key.encode("ascii"))

    def encrypt(self, secret: str) -> str:
        return self._fernet.encrypt(secret.encode("utf-8")).decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        return self._fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")

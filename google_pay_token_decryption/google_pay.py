import base64
import json
import time
from json.decoder import JSONDecodeError
from typing import Dict, List, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    ECDSA,
    SECP256R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_der_public_key,
)

ECv2_PROTOCOL_VERSION = "ECv2"


class GooglePayError(Exception):
    pass


def construct_signed_data(*args: str) -> bytes:
    """
    Construct the signed message from the list of its components by concatenating the
    byte length of each component in 4 bytes little-endian format plus the UTF-8 encoded
    component.

    See https://developers.google.com/pay/api/android/guides/resources/payment-data-cryptography#verify-signature
    for an example.
    """
    signed = b""
    for a in args:
        signed += len(a).to_bytes(4, byteorder="little")
        signed += bytes(a, "utf-8")
    return signed


def check_expiration_date_is_valid(expiration: str) -> bool:
    """
    Check that a timestamp in UTC milliseconds since epoch is after the current time.

    :return: True if expiration date is in the future, False otherwise.
    """
    current_time = time.time() * 1000
    return current_time < int(expiration)


def load_public_key(key: str) -> EllipticCurvePublicKey:
    derdata = base64.b64decode(key)
    return cast(EllipticCurvePublicKey, load_der_public_key(derdata, default_backend()))


def load_private_key(key: str) -> EllipticCurvePrivateKey:
    derdata = base64.b64decode(key)
    return cast(
        EllipticCurvePrivateKey, load_der_private_key(derdata, None, default_backend())
    )


class GooglePayTokenDecryptor:
    sender_id = "Google"
    algorithm = ECDSA(hashes.SHA256())

    def __init__(
        self,
        root_signing_keys: List[Dict],
        recipient_id: str,
        private_key: str,
    ):
        """
        Creates a new GooglePayTokenDecryptor instance.

        :param root_signing_keys: Google root signing keys
            (see https://developers.google.com/pay/api/android/guides/resources/payment-data-cryptography#root-signing-keys).
        :param recipient_id: "merchant:merchantId" where the merchantId matches
            the value found in the Google Pay Business Console. In Google's test environment
            this value is always "merchant:12345678901234567890".
        :param private_key: Base64-encoded private key corresponding to the public
            key submitted to the Google Pay console for the merchant.
        """
        self.root_signing_keys = root_signing_keys
        if not type(self.root_signing_keys) is list:
            raise GooglePayError("root_signing_keys must be a list")
        self._filter_root_signing_keys()

        self.recipient_id = recipient_id
        self.private_key = load_private_key(private_key)

    def decrypt_token(self, data: Dict, verify: bool = True) -> Dict:
        """
        Verifies the signature of a Google token and decrypts it according to
        the docs:
        https://developers.google.com/pay/api/android/guides/resources/payment-data-cryptography#decrypt-token

        :param dict: The encrypted token.
        :param verify: Whether the signature of the token should be verified (recommended) or not.
        :returns dict: The decrypted token.

        :raises Exception: if the token could not be verified or decrypted.
        """
        if verify:
            self.verify_signature(data)

        signed_message = json.loads(data["signedMessage"])
        for k in ["ephemeralPublicKey", "tag", "encryptedMessage"]:
            # Base64 decode the message fields
            signed_message[k] = base64.b64decode(signed_message[k])

        shared_key = self._get_shared_key(signed_message["ephemeralPublicKey"])
        derived_key = self._derive_key(signed_message["ephemeralPublicKey"], shared_key)
        symmetric_encryption_key = derived_key[:32]
        mac_key = derived_key[32:]

        self._verify_message_hmac(
            mac_key, signed_message["tag"], signed_message["encryptedMessage"]
        )

        decrypted = self._decrypt_message(
            symmetric_encryption_key, signed_message["encryptedMessage"]
        )

        try:
            decrypted_data = json.loads(decrypted)
        except JSONDecodeError:
            raise GooglePayError(
                f"Token payload does not contain valid JSON. Payload: '{decrypted.decode()}'"
            )

        if not check_expiration_date_is_valid(decrypted_data["messageExpiration"]):
            raise GooglePayError("Token message has expired.")

        return decrypted_data

    def _get_shared_key(self, ephemeral_public_key_bytes: bytes) -> bytes:
        """
        Use the private key and the given ephemeralPublicKey to
        derive a 512-bit long shared key that uses ECIES-KEM.
        """
        curve = (
            SECP256R1()  # Elliptic curve: NIST P-256, also known in OpenSSL as prime256v1.
        )
        ephemeral_public_key = EllipticCurvePublicKey.from_encoded_point(
            curve, ephemeral_public_key_bytes
        )

        return self.private_key.exchange(ECDH(), ephemeral_public_key)

    def _derive_key(
        self, ephemeral_public_key_bytes: bytes, shared_key: bytes
    ) -> bytes:
        """
        Derive a symmetric key using the HKDFwithSHA256 function.
        """
        return HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 512-bit long key
            salt=bytes(32),  # 32 zeroed bytes
            info=b"Google",
        ).derive(ephemeral_public_key_bytes + shared_key)

    def _verify_message_hmac(
        self, mac_key: bytes, tag: bytes, encrypted_message: bytes
    ) -> None:
        """
        Verify that the tag field is a valid MAC for encryptedMessage
        using HMAC with hash function SHA256.

        :raises: GooglePayError when the tag is not a valid MAC for the message.
        """
        h = hmac.HMAC(mac_key, hashes.SHA256())
        h.update(encrypted_message)
        try:
            h.verify(tag)
        except InvalidSignature:
            raise GooglePayError("Tag is not a valid MAC for the encrypted message")

    def _decrypt_message(
        self, symmetric_encryption_key: bytes, encrypted_message: bytes
    ) -> bytes:
        """
        Decrypt encryptedMessage with the use of AES-256-CTR mode.
        """
        cipher = Cipher(algorithms.AES(symmetric_encryption_key), modes.CTR(bytes(16)))
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_message) + decryptor.finalize()

    def verify_signature(self, data: Dict) -> None:
        """
        Verifies the signatures of a Google Pay token according to:
        https://developers.google.com/pay/api/android/guides/resources/payment-data-cryptography#signature-verification

        :param data: Encrypted data received from Google Pay.

        :raises: An exception if the signatures could not be verified.
        """
        if data["protocolVersion"] != ECv2_PROTOCOL_VERSION:
            raise GooglePayError(
                f"Only {ECv2_PROTOCOL_VERSION}-signed tokens are supported, but token is {data['protocolVersion']}-signed."
            )

        self._verify_intermediate_signing_key(data)
        signed_key = self._validate_intermediate_signing_key(data)
        self._verify_message_signature(signed_key, data)

    def _verify_intermediate_signing_key(self, data: Dict) -> None:
        """
        Verify the intermediate signing key according to the docs:
        https://developers.google.com/pay/api/android/guides/resources/payment-data-cryptography#verify-signature

        :param data: Encrypted Google Pay token.

        :raises: GooglePayError if the intermediate signing key could not
            be verified.
        """
        signatures = [
            base64.decodebytes(bytes(s, "utf-8"))
            for s in data["intermediateSigningKey"]["signatures"]
        ]
        signed_key = data["intermediateSigningKey"]["signedKey"]
        signed_data = construct_signed_data(
            self.sender_id, data["protocolVersion"], signed_key
        )

        # Check if any of the signatures are valid for any of the root signing keys
        for key in self.root_signing_keys:
            public_key = load_public_key(key["keyValue"])
            for signature in signatures:
                try:
                    public_key.verify(signature, signed_data, self.algorithm)
                except (ValueError, InvalidSignature):
                    # Invalid signature. Try the other signatures.
                    ...
                else:
                    # Valid signature was found
                    return

        raise GooglePayError("Could not verify intermediate signing key signature")

    def _validate_intermediate_signing_key(self, data: Dict) -> Dict:
        """
        Check that the intermediate signing key hasn't expired

        :return: The JSON-loaded intermediate signed key.

        :raises: GooglePayError if the intermediate signing key has expired.
        """
        signed_key = json.loads(data["intermediateSigningKey"]["signedKey"])
        if not check_expiration_date_is_valid(signed_key["keyExpiration"]):
            raise GooglePayError("Intermediate signing key has expired")
        return signed_key

    def _verify_message_signature(self, signed_key: Dict, data: Dict) -> None:
        """
        Verify the message signature according to:
        https://developers.google.com/pay/api/android/guides/resources/payment-data-cryptography#verify-signature

        :raises: An exception when the message signature could not be verified.
        """
        public_key = load_public_key(signed_key["keyValue"])
        signature = base64.decodebytes(bytes(data["signature"], "utf-8"))
        signed_data = construct_signed_data(
            self.sender_id,
            self.recipient_id,
            data["protocolVersion"],
            data["signedMessage"],
        )
        try:
            public_key.verify(signature, signed_data, self.algorithm)
        except Exception:
            raise GooglePayError("Could not verify message signature")

    def _filter_root_signing_keys(self) -> None:
        """
        Filter the root signing keys to get only the keys that use ECv2 protocol
        and that either doesn't expire or has an expiry date in the future.
        """
        self.root_signing_keys = [
            key
            for key in self.root_signing_keys
            if key["protocolVersion"] == ECv2_PROTOCOL_VERSION
            and (
                "keyExpiration" not in key
                or check_expiration_date_is_valid(key["keyExpiration"])
            )
        ]
        if len(self.root_signing_keys) == 0:
            raise GooglePayError(
                f"At least one root signing key must be {ECv2_PROTOCOL_VERSION}-signed and have a valid expiration date."
            )

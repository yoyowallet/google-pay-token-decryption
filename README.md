# Google Pay token decryption

A Python package to decrypt Google Pay tokens according to the [Google Pay docs](https://developers.google.com/pay/api/android/guides/resources/payment-data-cryptography#decrypt-token) using the [`pyca/cryptography`](https://cryptography.io/en/latest/) package.

## System requirements

- Python 3.8+

## Usage

1. Install the package using Pip: `pip install google-pay-token-decryption`.

2. Get latest Google root signing keys [here](https://developers.google.com/pay/api/android/guides/resources/payment-data-cryptography#root-signing-keys).

3. Get your **merchant ID/recipient ID** from the [Google Pay business console](https://pay.google.com/business/console). It should be in the format "merchant:<your merchant ID>". In Google's test environment it is always "merchant:12345678901234567890".

4. Generate your merchant private and public keys by following [this documentation](https://developers.google.com/pay/api/android/guides/resources/payment-data-cryptography#using-openssl).

5. Create a new `GooglePayTokenDecryptor` object and decrypt a token using the `decrypt_token` method:

```python
from google_pay_token_decryption import GooglePayTokenDecryptor

# Instantiate using the a list of root signing keys, your recipient ID and private key
root_signing_keys = [{
    "keyValue": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw==",
    "keyExpiration": "32506264800000",
    "protocolVersion": "ECv2",
}]
recipient_id = "someRecipient"
private_key = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPSuFr4iSIaQprjjchHPyDu2NXFe0vDBoTpPkYaK9dehRANCAATnaFz/vQKuO90pxsINyVNWojabHfbx9qIJ6uD7Q7ZSxmtyo/Ez3/o2kDT8g0pIdyVIYktCsq65VoQIDWSh2Bdm"
decryptor = GooglePayTokenDecryptor(root_signing_keys, recipient_id, private_key)

# Verify and decrypt a token 
encrypted_token = {
    "signature": "MEYCIQCbtFh9UIf1Ty3NKZ2z0ZmL0SHwR30uiRGuRXk9ghpyrwIhANiZQ0Df6noxkQ6M652PcIPkk2m1PQhqiq4UhzvPQOYf",
    "intermediateSigningKey": {
        "signedKey": "{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw==\",\"keyExpiration\":\"1879409613939\"}",
        "signatures": [
            "MEQCIFBle+JsfsovRBeoFEYKWFAeBYFAhq0S+GtusiosjV4lAiAGcK9qfVpnqG6Hw8cbGBQ79beiAs6IIkBxBfeKDBR+kA=="
        ]
    },
    "protocolVersion": "ECv2",
    "signedMessage": "{\"encryptedMessage\":\"PeYi+ZnJs1Gei1dSOkItdfFG8Y81FvEI7dHE0sSrSU6OPnndftV/qDbbmXHmppoyP/2lhF+XsH93qzD3u46BRnxxPtetzGT0533rIraskTj8SZ6FVYY1Opfo7FECGk57FfF8aDaCSOoyTh1k0v6wdxVwEVvWqG1T/ij+u2KWOw5G1WSB/RVicni0Az13ModYb0KMdMws1USKlWxBfKU5PtxibVx4fZ95HYQ82qgHlV4ToKaUY7YWud1iEspmFsBMk0nh4t1hVxRzsxKUjMV1915qD5yq7k5n9YPao2mR9NJgLPDktsc4uf9bszzvnqhz3T1YID43QwX16yCyn/YxNVe3dJ1+S+BGyJ+vyKXp+Zh4SlIua2NFLwnR06Es3Kvl6LlOGasoPC/tMAWYLQlGsl+vHK3mrMZjC6KbOsXg+2mrlZwL+QOt3ih2jIPe\",\"ephemeralPublicKey\":\"BD6pQKpy7yDebAX4qV0u/AfMYNQhOD+teyoa/5SsxwTGCoC1ZKHxNMb5BXvRmBcYGPNTx8+fAkEwzJ8GqbX/Q7E=\",\"tag\":\"8gFteCvCuamX1RmL7ORdHqleyBf0N55OfAs80RYGgwc=\"}"
}
decrypted_token = decryptor.decrypt_token(encrypted_token)
print(decrypted_token)
"""
{
    "messageExpiration": "32506264800000",
    "messageId": "AH2EjtfkY514K5lmPF4NOP9lMR5tPedsjQR719hIzI-zB1g0A-TBlYInGQuEVQeIWGlajqEpvSyrl3r_iN0RxoV9RYjxqnzG-kXmcBNkferp4NfNjVqxYrVT0e5JRzU3dQjkb0tQWOxN",
    "paymentMethod": "CARD",
    "paymentMethodDetails": {
        "expirationYear": 2026,
        "expirationMonth": 12,
        "pan": "4111111111111111",
        "authMethod": "PAN_ONLY"
    }
}
"""
```

## Contributing

See [Contributing](./CONTRIBUTING.md)
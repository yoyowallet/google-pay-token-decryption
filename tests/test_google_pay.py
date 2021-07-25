import datetime

import pytest

from google_pay_token_decryption.google_pay import (
    ECv2_PROTOCOL_VERSION,
    GooglePayError,
    GooglePayTokenDecryptor,
    check_expiration_date_is_valid,
)


def datetime_to_milliseconds(input_date: datetime.datetime):
    return str(int(input_date.timestamp() * 1000))


valid_signature = "MEQCIFBle+JsfsovRBeoFEYKWFAeBYFAhq0S+GtusiosjV4lAiAGcK9qfVpnqG6Hw8cbGBQ79beiAs6IIkBxBfeKDBR+kA=="

valid_root_signing_key = {
    "keyValue": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw==",
    "keyExpiration": "32506264800000",
    "protocolVersion": "ECv2",
}


@pytest.fixture
def encrypted_token():
    return {
        "signature": "MEYCIQCbtFh9UIf1Ty3NKZ2z0ZmL0SHwR30uiRGuRXk9ghpyrwIhANiZQ0Df6noxkQ6M652PcIPkk2m1PQhqiq4UhzvPQOYf",
        "intermediateSigningKey": {
            "signedKey": '{"keyValue":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw==","keyExpiration":"1879409613939"}',
            "signatures": [valid_signature],
        },
        "protocolVersion": "ECv2",
        "signedMessage": '{"encryptedMessage":"PeYi+ZnJs1Gei1dSOkItdfFG8Y81FvEI7dHE0sSrSU6OPnndftV/qDbbmXHmppoyP/2lhF+XsH93qzD3u46BRnxxPtetzGT0533rIraskTj8SZ6FVYY1Opfo7FECGk57FfF8aDaCSOoyTh1k0v6wdxVwEVvWqG1T/ij+u2KWOw5G1WSB/RVicni0Az13ModYb0KMdMws1USKlWxBfKU5PtxibVx4fZ95HYQ82qgHlV4ToKaUY7YWud1iEspmFsBMk0nh4t1hVxRzsxKUjMV1915qD5yq7k5n9YPao2mR9NJgLPDktsc4uf9bszzvnqhz3T1YID43QwX16yCyn/YxNVe3dJ1+S+BGyJ+vyKXp+Zh4SlIua2NFLwnR06Es3Kvl6LlOGasoPC/tMAWYLQlGsl+vHK3mrMZjC6KbOsXg+2mrlZwL+QOt3ih2jIPe","ephemeralPublicKey":"BD6pQKpy7yDebAX4qV0u/AfMYNQhOD+teyoa/5SsxwTGCoC1ZKHxNMb5BXvRmBcYGPNTx8+fAkEwzJ8GqbX/Q7E=","tag":"8gFteCvCuamX1RmL7ORdHqleyBf0N55OfAs80RYGgwc="}',
    }


encrypted_expired_token = {
    "signature": "MEUCIQCv+gDxUajhYqBcI2tt6zMCekinJsaYL31/aBtS74YN4QIgIZGFztAVTgyV2CB51NIfTtSzQBxNA52P4R8H7K5N/jE=",
    "intermediateSigningKey": {
        "signedKey": '{"keyValue":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw==","keyExpiration":"1880104348293"}',
        "signatures": [
            "MEUCIQDpPpV60rY2VLeDKcM3YNmAs+07Qsr8ZVoj8ZDNFcTCAQIgeVH3C/zUVWSIyd+/nO+AlMAemtcfUCX+71VWEF3T4yI="
        ],
    },
    "protocolVersion": "ECv2",
    "signedMessage": '{"encryptedMessage":"eYKTj3VRk9b4EbvYped0pHvw8ZZTMqRtK6xZ1wzuvNHB3vQHrClYA5wZeujpzwM17SV9HpEzk1r2cKzZC+fpQpoLXk+XWjrPwKUGnPNDLW9aGcNVMqQZrspduLYnZ+SljnIxIBPS13APS70FUaEIj+WZ6HTe7rjhtPOFRJhs0LO5Q4PsGgkpK5d7hw6GNcpaFaVIolaFvHyg7spC9+U7F9fbOcDu1lCx67DjsKoiRPbToXfdu9mgPro0UT5RdTZGdydeijlKBwlv3xToq3M5w7xI2GyaPfvRrQmguADTlCLUL/g0IEYxWXDz/SvpKzU5olLP1lZ+Jpvu+Ah9HYhwyOAetMiCVSEolYjveKDJM0tRnixTOvWtQ1c9ezBkIjyl/iC3Kc+uDliswZeC7E6FHqb0sVs/IfImwO5kEdRgi138t6Ztl2Mvz1muMJ22avYw1wlhU6+46k+b8iirTD8WifVd2rEj19o6kMikFlo43rgz7aYtWNZnIFE//BSBy+eNvG0/aFrFdevrNiboxn++B1A=","ephemeralPublicKey":"BDMecFYEc1K+22fvcZImwfrRTa0r4Tiay/fFH3W+Ktnd/Zl1uiq4XwfvTfJwJB50elBmmyY43MdlyZjqiZjWJsw=","tag":"CW+gKSA9fvg4zX+9QBZwtmYcEvLGlTywopwWZIVZwhQ="}',
}

encrypted_plaintext = {
    "signature": "MEUCIE9yZoaWuT+xS8GRAeFMhox/FYmmHaZqSjD/g4fJBBAeAiEAiuQzXoPWRSB6AhSD81q2bUOTLK4k+MntQx2UERk67fE=",
    "intermediateSigningKey": {
        "signedKey": '{"keyValue":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw==","keyExpiration":"1880104972775"}',
        "signatures": [
            "MEYCIQC70Y6VnxvXnwQ5HgJCD6HxPa2EMDCU6AVk6gAFi/A2TwIhAIvAbw5VShuO6uf8N0qJ8l8oVT3TMBX2Zv28+FKlvnRL"
        ],
    },
    "protocolVersion": "ECv2",
    "signedMessage": '{"encryptedMessage":"ssCh5UO4l4Xp","ephemeralPublicKey":"BKg85WIik76zjAKEFehNZ4seOh2/RX8WNPpX1gBzgQlsZCNYCj/2O8TsbDxYI2c9L5yBSpJOLy6AOE3q+5m3idg=","tag":"yRYHWOnuDsx6/KjS7axdL8YIPXuMnExw6FDldolRl+M="}',
}

encrypted_invalid_tag = {
    "signature": "MEQCIGZJz6qTyiMeVzlwJ2FQtUUh5bfORrT7/ZW7iqtAOa7JAiBBOTPXLNr/gfgEmlAfUW6c7OpwriuYzW8SUMWNz6Qy3g==",
    "intermediateSigningKey": {
        "signedKey": '{"keyValue":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw==","keyExpiration":"1880106295412"}',
        "signatures": [
            "MEUCIQCJihoRFfDp170pXqtUn0u9eDX8pU5r06HzcSisttR+fwIgQH9ROgfNj69y3HSWOiSVGbSYQ/XD6kvWDHI43Qo9CpQ="
        ],
    },
    "protocolVersion": "ECv2",
    "signedMessage": '{"encryptedMessage":"wFnzlFi/al6Kwk8/VFZp5R25WqN8eWQzRBZpjHbzDYMYeI97DeMEewI0BevsAgbQkJG03ktxOvUcFGjWVc/tePDBJUKYZDWwNosvRV4LgUkC7n7ByGntSJ/ekqXlm48UDAOPYchRTG6KvMdtYAfZQ5TbggbmLiJkvO55eHwyBHbgYiERJMQLh50QTp2peL7ZC7f8lBZ0Z3VWSEDLyFza93uadlzMEdhjXcgWwxIWAtxmMFvdLaXn0Crp7m0b90CfbcBSzsf4OeVbbUA8PoFhYJ9qjRErA+4MO+cXvtl3+AwiudVs3MtsvZX2Be/LniKHZoGNz34gn2+MTd9tGeiw3kRBYgwOVMciVcXtiq47XCcj5ttszfXctbNzuCS+MTDp0V3W0T/i9B2Vj6ocFFTOqvTz8AtMDfphXoSGAV+txv4S8iclFjKiMXHJw6dmI/deabisdXPoqAhpdfO3DGlO48NQF4Fwo0qUCwTdVeZ3HNYD0NYYKt6eKghdrXZFcDaE9FPs1xVFYUzJeupV2+Kpr9J9vA==","ephemeralPublicKey":"BC7Gy3uiwBWRh1qYRoJ8DhD05XSr2RjW2NcNIKXhxx1gfsp1BuET9uxaFvujKFTFSAPSYdYSRYB4mDzb7rO+12I=","tag":"AYcBmZRnlcPtU/t/CWUQJMDM6BjNEH3klAE1HxlvXPc="}',
}

decrypted_google_pay_token = {
    "messageExpiration": "32506264800000",
    "messageId": "AH2EjtfkY514K5lmPF4NOP9lMR5tPedsjQR719hIzI-zB1g0A-TBlYInGQuEVQeIWGlajqEpvSyrl3r_iN0RxoV9RYjxqnzG-kXmcBNkferp4NfNjVqxYrVT0e5JRzU3dQjkb0tQWOxN",
    "paymentMethod": "CARD",
    "paymentMethodDetails": {
        "expirationYear": 2026,
        "expirationMonth": 12,
        "pan": "4111111111111111",
        "authMethod": "PAN_ONLY",
    },
}


@pytest.fixture
def encrypted_google_pay_token_with_expired_intermediate_signature():
    """
    Generated using the sealECV2 method in the Java Tink library:
    https://github.com/google/tink/blob/06aa21432e1985fea4ab26c26f6038895b22cce0/apps/paymentmethodtoken/src/test/java/com/google/crypto/tink/apps/paymentmethodtoken/PaymentMethodTokenRecipientTest.java#L1042-L1059
    """
    return {
        "signature": "MEQCIADUoxj1TKGFieh3aPn4rShKyM6bGtHi+SabRnvAlB33AiAIgjQIfZ7hMDOuxMXC/lrm4COrqH/PJ4vRtmBZn9438Q==",
        "intermediateSigningKey": {
            "signedKey": '{"keyValue":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw==","keyExpiration":"1361023457681"}',
            "signatures": [
                "MEYCIQD3fluX1fLwuuo/oCuyifmGM1xisLNylRZ5902dbjabSQIhAOuDBulLTtF5vuo6TxFBD/s3J4PqVzBC5y5d28Y4adsN"
            ],
        },
        "protocolVersion": "ECv2",
        "signedMessage": '{"encryptedMessage":"2aZvfZU49a0/Pi+Jl/1qFWK5faeDQvpWeXW+BcWDRVaYeqV4oAgfzp0Z0v6KPZMu/9bWeuHVRlymQruiqPHJlggCb3syo0HOz2ls59YEpTWfSZsWEGwhoiIbrrcZ953IQ1gxzaahYt6mAXIlHwAujhyqBcw8QdkzPgnr2PJhDHIGioy2u4iHnWHhvJkdcwbmtifd+pS/KDzN40ipFhaYwFPikRi9Br5vT1SEEbOH4UCY5ceJH3ZQJeaWCBYYrJU8ZpJjFXvOerRxLB995lNMHYDHV5jh5i3CMv7Sb4CjrVUy3ld7zhXOlDtRSbwze5aaFUqGjEIoIlwO56pB5qPCXAj/zjT67K5HGfx0/yc8hzT+RAc0lLCrIjBW9SWxPzq8hzhTWbsmI9hp8UcEO/H+EdlL0i8ENVXSRehCl7/LEEJKS3EBRR3h7W1ojZtl","ephemeralPublicKey":"BPxDq7BdXa7TBuY4PdlQVqfLjpgSNvC5TJgWZ6WetuR269iQHZVxohMbgUlHl1Hbs2JpXwPNpDLgzHOizvi+aAw=","tag":"IiMYvCc3gEvR4P3xhF5DaN/cyjOc++NJmqxthrbdc0U="}',
    }


@pytest.fixture
def root_signing_keys():
    return [valid_root_signing_key]


@pytest.fixture
def private_key():
    return "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPSuFr4iSIaQprjjchHPyDu2NXFe0vDBoTpPkYaK9dehRANCAATnaFz/vQKuO90pxsINyVNWojabHfbx9qIJ6uD7Q7ZSxmtyo/Ez3/o2kDT8g0pIdyVIYktCsq65VoQIDWSh2Bdm"


@pytest.fixture
def recipient_id():
    return "someRecipient"


@pytest.fixture
def google_pay_token_decryptor(root_signing_keys, recipient_id, private_key):
    return GooglePayTokenDecryptor(root_signing_keys, recipient_id, private_key)


class TestGooglePayTokenDecryptor(object):
    @pytest.mark.parametrize(
        ("invalid_root_signing_keys", "error_message"),
        [
            ("keys", "root_signing_keys must be a list"),
            (
                [
                    {
                        "keyValue": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw==",
                        "keyExpiration": datetime_to_milliseconds(
                            datetime.datetime(2000, 1, 1)
                        ),
                        "protocolVersion": "ECv2",
                    }
                ],
                f"At least one root signing key must be {ECv2_PROTOCOL_VERSION}-signed and have a valid expiration date.",
            ),
        ],
    )
    def test_init_root_signing_keys_validation(
        self, recipient_id, invalid_root_signing_keys, private_key, error_message
    ):
        with pytest.raises(GooglePayError, match=error_message):
            GooglePayTokenDecryptor(
                invalid_root_signing_keys, recipient_id, private_key
            )

    def test_init_filter_root_signing_keys(self, recipient_id, private_key):
        # GIVEN a list of keys
        non_expired_ecv2_key = {
            "keyValue": "abcd",
            "keyExpiration": datetime_to_milliseconds(datetime.datetime(2040, 1, 1)),
            "protocolVersion": "ECv2",
        }
        expired_key = {
            "keyValue": "abcd",
            "keyExpiration": datetime_to_milliseconds(datetime.datetime(2010, 1, 1)),
            "protocolVersion": "ECv2",
        }
        non_ecv2_key = {
            "keyValue": "abcd",
            "keyExpiration": datetime_to_milliseconds(datetime.datetime(2040, 1, 1)),
            "protocolVersion": "ECv1",
        }

        keys = [non_expired_ecv2_key, expired_key, non_ecv2_key]

        # WHEN the GooglePayTokenDecryptor is created
        decryptor = GooglePayTokenDecryptor(keys, recipient_id, private_key)

        # THEN the invalid keys are filtered out
        assert decryptor.root_signing_keys == [non_expired_ecv2_key]

    @pytest.mark.parametrize(
        ("intermediate_signing_key_signatures"),
        [
            (
                [
                    valid_signature,
                ]
            ),
            (
                [
                    "invalid-signature",  # Only one signature needs to be valid
                    valid_signature,
                ]
            ),
        ],
    )
    def test_verify_signature__success(
        self,
        encrypted_token,
        google_pay_token_decryptor,
        intermediate_signing_key_signatures,
    ):
        encrypted_token["intermediateSigningKey"][
            "signatures"
        ] = intermediate_signing_key_signatures
        google_pay_token_decryptor.verify_signature(encrypted_token)
        # No exceptions will be raised if at least one signature is valid
        assert True

    def test_verify_signature__intermediate_key_expired(
        self,
        encrypted_google_pay_token_with_expired_intermediate_signature,
        google_pay_token_decryptor,
    ):
        with pytest.raises(
            GooglePayError, match="Intermediate signing key has expired"
        ):
            google_pay_token_decryptor.verify_signature(
                encrypted_google_pay_token_with_expired_intermediate_signature
            )

    def test_verify_signature__invalid_intermediate_signature(
        self, encrypted_token, google_pay_token_decryptor
    ):
        encrypted_token["intermediateSigningKey"]["signatures"][0] = "invalid-signature"
        with pytest.raises(
            GooglePayError, match="Could not verify intermediate signing key signature"
        ):
            google_pay_token_decryptor.verify_signature(encrypted_token)

    def test_verify_signature__invalid_signature(
        self, encrypted_token, google_pay_token_decryptor
    ):
        encrypted_token["signature"] = "invalid-signature"
        with pytest.raises(GooglePayError, match="Could not verify message signature"):
            google_pay_token_decryptor.verify_signature(encrypted_token)

    def test_verify_signature__invalid_protocol(
        self, encrypted_token, google_pay_token_decryptor
    ):
        encrypted_token["protocolVersion"] = "ECv1"
        with pytest.raises(
            GooglePayError,
            match=f"Only {ECv2_PROTOCOL_VERSION}-signed tokens are supported, but token is {encrypted_token['protocolVersion']}-signed.",
        ):
            google_pay_token_decryptor.verify_signature(encrypted_token)

    def test_decrypt_token__success(
        self,
        encrypted_token,
        google_pay_token_decryptor,
    ):
        assert (
            google_pay_token_decryptor.verify_and_decrypt_token(encrypted_token)
            == decrypted_google_pay_token
        )

    @pytest.mark.parametrize(
        ("encrypted_token", "reason"),
        [
            (encrypted_expired_token, "Token message has expired."),
            (
                encrypted_plaintext,
                "Token payload does not contain valid JSON. Payload: 'plaintext'",
            ),
            (encrypted_invalid_tag, "Tag is not a valid MAC for the encrypted message"),
        ],
    )
    def test_decrypt_token__fail(
        self, google_pay_token_decryptor, encrypted_token, reason
    ):
        with pytest.raises(GooglePayError, match=reason):
            google_pay_token_decryptor.verify_and_decrypt_token(encrypted_token)


@pytest.mark.parametrize(
    ("expiration", "expired"),
    [
        (datetime_to_milliseconds(datetime.datetime(2040, 1, 1)), True),
        (datetime_to_milliseconds(datetime.datetime(2000, 1, 1)), False),
        (datetime_to_milliseconds(datetime.datetime(2019, 12, 1)), False),
    ],
)
def test_check_expiration_date_is_valid(expiration, expired):
    assert check_expiration_date_is_valid(expiration) == expired

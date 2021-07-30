from base64 import b64decode
from ecdsa import VerifyingKey
from ecdsa.util import sigdecode_der
import hashlib
import json
import re

request_signature_header_regex = re.compile(r"ecdsa=([0-9A-Za-z+/=]+)")
gateway_key_file = "gateway-public-key.json"


def verify_signature(request_body, headers):
    """Verify a payment gateway callback signature.

    request_body: Byte string containing the payload of the callback request.
    headers: Dict containing the HTTP headers from the callback request.

    Return True if the signature matches the request body."""

    pem = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJxzXoZ/LFxPXvfJ2MBMjhptT691J178zwID1EbO0MeB/fbhL8y3hqRWlIg0wTNq8NjWXlAjzjQ/qUxHq82xTMQ=="

    verifying_key = VerifyingKey.from_pem(pem)

    matches = request_signature_header_regex.match(headers["Request-Signature"])
    if not matches:
        raise Exception("Request-Signature header value invalid")

    base64Sig = matches.group(1)

    der_signature = b64decode(base64Sig)

    print([ x for x in der_signature])
    print("\n\n\n")
    print([x for x in request_body])

    return verifying_key.verify(
        der_signature, request_body, hashfunc=hashlib.sha256, sigdecode=sigdecode_der
    )

if __name__ == "__main__":
    headers = {
        "Request-Signature": "ecdsa=MEYCIQD7y3DQMfRR4n/RSb+3F7vdpm0IyZ1a0ojJ+eyByu2zRQIhAI6fhLGyzemSYBBOuOAx1V0QFRJaEeGbPKYSSnlxN97b",
        "Key-ID": "JwiUFiAG4KH"
    }

    request_str = '{"clientId":"privalgo-test","requestId":"8","timestamp":"2021-07-30T04:05:51.491Z","callbackArgs":"TestArgs","transactions":[{"transactionId":"t8","transactionType":"pay","statusCode":112,"statusDescription":"The transaction is being reviewed.","provider":"test","statusType":"pending","finished":false}],"finished":false}'

    print(verify_signature(request_str.encode(), headers))

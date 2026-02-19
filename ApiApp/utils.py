import base64
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from pyattest.assertion import Assertion
from pyattest.configs.apple import AppleConfig
from rest_framework_simplejwt.tokens import RefreshToken
from pyattest.attestation import Attestation
from pyattest.exceptions import PyAttestException

from ApiCore.settings import PLAY_INTEGRITY_CONFIG, APP_ATTEST_APP_ID, DEBUG


class AttestationHandler:
    """
    Verify attestation using Play Integrity (Android) or App Attest (iOS). In case of iOS allows extraction of
    public key after attestation for further assertions using get_public_key()

    Parameters:
        nonce: nonce used to encode the token
        platform: device's platform
        attestation_token:
            Android: JWT from Play Integrity, iOS: generated attestation
        assertion_token:
            iOS only: generated assertion, available only when device has already been attested before with the
            same key_id
        key_id:
            iOS only: generated public key identifier
        public_key:
            iOS only, if the device has already been attested before with same key_id
    """
    def __init__(
            self,
            nonce: str,
            platform: Literal["android", "ios"],
            attestation_token: str | None = None,
            assertion_token: str | None = None,
            key_id: str | None = None,
            public_key: EllipticCurvePublicKey | None = None
    ):
        if platform == "android" and attestation_token is None:
            raise ValueError("attestation_token is required when platform is Android")

        if (platform == "ios" and
                (attestation_token is None or key_id is None) and
                (assertion_token is None or public_key is None)):
            raise ValueError(
                "attestation_token+key_id or assertion_token+public_key are required when platform is iOS"
            )

        self._nonce = base64.urlsafe_b64decode(nonce + "==")
        self._platform = platform
        self._attestation_token = attestation_token
        self._assertion_token = assertion_token
        self._key_id = base64.urlsafe_b64decode(key_id + "==")

        self._public_key = public_key

    def multiplatform_verify(self) -> bool:
        if self._platform == "android":
            return self.verify_android_attestation()
        elif self._platform == "ios":
            if self._public_key is None:
                return self.verify_ios_attestation()
            else:
                return self.verify_ios_assertion()

        else:
            return False

    def verify_android_attestation(self) -> bool:
        if self._platform != "android":
            return False

        attestation = Attestation(
            self._attestation_token,
            self._nonce,
            PLAY_INTEGRITY_CONFIG
        )

        try:
            attestation.verify()
            return True

        except PyAttestException:
            return False

    def verify_ios_attestation(self) -> bool:
        if self._platform != "ios":
            return False

        config = AppleConfig(
            self._key_id,
            APP_ATTEST_APP_ID,
            not DEBUG
        )

        attestation = Attestation(
            self._attestation_token,
            self._nonce,
            config
        )

        try:
            attestation.verify()

            self._public_key = attestation.data.get("certs")[0].public_key
            return True

        except PyAttestException:
            return False

    def verify_ios_assertion(self) -> bool:
        if self._platform != "ios" or self._public_key is None:
            return False

        config = AppleConfig(
            self._key_id,
            APP_ATTEST_APP_ID,
            not DEBUG
        )

        assertion = Assertion(
            base64.urlsafe_b64decode(self._assertion_token + "=="),
            self._nonce,
            self._public_key,
            config
        )

        try:
            assertion.verify()
            return True

        except PyAttestException:
            return False

    def get_public_key(self) -> EllipticCurvePublicKey | None:
        return self._public_key


def generate_device_jwt(device_id: str, platform: Literal["android", "ios"]) -> tuple[str, str]:
    """
    Generate JWT access and refresh token pair for a device

    Parameters:
        device_id:
        platform: device's platform

    Returns:
        (str, str): access token, refresh token
    """

    refresh = RefreshToken()

    refresh['device_id'] = str(device_id)
    refresh['type'] = platform

    access = refresh.access_token
    return str(access), str(refresh)

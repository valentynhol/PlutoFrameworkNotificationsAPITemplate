import base64
import logging
from hashlib import sha256
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from pyattest.assertion import Assertion
from pyattest.configs.apple import AppleConfig
from rest_framework_simplejwt.tokens import RefreshToken
from pyattest.attestation import Attestation
from pyattest.exceptions import PyAttestException

from ApiCore.settings import PLAY_INTEGRITY_CONFIG, APP_ATTEST_APP_ID, DEBUG

logger = logging.getLogger(__name__)


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
        logger.debug(f"AttestationHandler init: platform={platform}")

        if platform == "android" and attestation_token is None:
            logger.debug("Android but attestation_token is None")
            raise ValueError("attestation_token is required when platform is Android")

        if (platform == "ios" and
                (attestation_token is None or key_id is None) and
                (assertion_token is None or public_key is None)):
            logger.debug(
                f"iOS init invalid state: "
                f"attestation_token={bool(attestation_token)}, "
                f"key_id={bool(key_id)}, "
                f"assertion_token={bool(assertion_token)}, "
                f"public_key={bool(public_key)}"
            )
            raise ValueError(
                "attestation_token+key_id or assertion_token+public_key are required when platform is iOS"
            )

        try:
            self._nonce = urlsafe_b64decode_padded(nonce)
            logger.debug("Nonce base64 decoded successfully")
        except Exception:
            logger.exception("Nonce base64 decode failed")
            raise

        self._platform = platform
        self._attestation_token = attestation_token
        self._assertion_token = assertion_token

        try:
            self._key_id = urlsafe_b64decode_padded(key_id)
        except Exception:
            logger.exception("key_id base64 decode failed")
            raise

        self._public_key = public_key

    def multiplatform_verify(self) -> bool:
        logger.debug(
            f"multiplatform_verify called | "
            f"platform={self._platform} | "
            f"has_public_key={self._public_key is not None}"
        )

        if self._platform == "android":
            logger.debug("Routing to verify_android_attestation")
            return self.verify_android_attestation()

        elif self._platform == "ios":
            if self._public_key is None:
                logger.debug("Routing to verify_ios_attestation (no public key yet)")
                return self.verify_ios_attestation()
            else:
                logger.debug("Routing to verify_ios_assertion (public key exists)")
                return self.verify_ios_assertion()

        else:
            logger.error(f"Unknown platform: {self._platform}")
            return False

    def verify_android_attestation(self) -> bool:
        logger.debug("verify_android_attestation called")

        if self._platform != "android":
            logger.error("verify_android_attestation called on non-android platform")
            return False

        logger.debug(
            f"Android attestation | "
            f"token_present={self._attestation_token is not None} | "
            f"nonce_length={len(self._nonce) if self._nonce else 0}"
        )

        try:
            attestation = Attestation(
                self._attestation_token,
                self._nonce,
                PLAY_INTEGRITY_CONFIG
            )

            logger.debug("Attestation object created, starting verify()")
            attestation.verify()

            logger.debug("Android attestation verification SUCCESS")
            return True

        except PyAttestException as e:
            logger.exception(f"Android attestation verification FAILED: {str(e)}")
            return False

        except Exception as e:
            logger.exception(f"Unexpected error during Android verification: {str(e)}")
            return False

    def verify_ios_attestation(self) -> bool:
        logger.debug("verify_ios_attestation called")

        if self._platform != "ios":
            logger.error("verify_ios_attestation called on non-ios platform")
            return False

        logger.debug(
            f"iOS attestation | "
            f"has_key_id={self._key_id is not None} | "
            f"nonce_length={len(self._nonce) if self._nonce else 0} | "
            f"debug_mode={DEBUG}"
        )

        try:
            config = AppleConfig(
                self._key_id,
                APP_ATTEST_APP_ID,
                not DEBUG
            )

            logger.debug("AppleConfig created")

            attestation = Attestation(
                urlsafe_b64decode_padded(self._attestation_token),
                self._nonce,
                config
            )

            logger.debug("Attestation object created, starting verify()")
            attestation.verify()

            certs = attestation.data.get("certs")
            if not certs:
                logger.error("No certificates returned in attestation data")
                return False

            self._public_key = x509.load_der_x509_certificate(certs[-1].dump()).public_key()
            logger.debug("iOS attestation verification SUCCESS, public key extracted")

            return True

        except PyAttestException as e:
            logger.exception(f"iOS attestation verification FAILED: {str(e)}")
            return False

        except Exception as e:
            logger.exception(f"Unexpected error during iOS attestation: {str(e)}")
            return False

    def verify_ios_assertion(self) -> bool:
        logger.debug("verify_ios_assertion called")

        if self._platform != "ios":
            logger.error("verify_ios_assertion called on non-ios platform")
            return False

        if self._public_key is None:
            logger.error("verify_ios_assertion called but public_key is None")
            return False

        logger.debug(
            f"iOS assertion | "
            f"assertion_present={self._assertion_token is not None} | "
            f"nonce_length={len(self._nonce) if self._nonce else 0} | "
            f"debug_mode={DEBUG}"
        )

        try:
            config = AppleConfig(
                self._key_id,
                APP_ATTEST_APP_ID,
                not DEBUG
            )

            assertion = Assertion(
                urlsafe_b64decode_padded(self._assertion_token),
                sha256(self._nonce).digest(),
                self._public_key,
                config
            )

            logger.debug("Assertion object created, starting verify()")
            assertion.verify()

            logger.debug("iOS assertion verification SUCCESS")
            return True

        except PyAttestException as e:
            logger.exception(f"iOS assertion verification FAILED: {str(e)}")
            return False

        except Exception as e:
            logger.exception(f"Unexpected error during iOS assertion: {str(e)}")
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


def urlsafe_b64decode_padded(s: str) -> bytes:
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

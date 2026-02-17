from typing import Literal

from rest_framework_simplejwt.tokens import RefreshToken
from pyattest.attestation import Attestation
from pyattest.exceptions import PyAttestException

from ApiCore.settings import PLAY_INTEGRITY_CONFIG, APP_ATTEST_CONFIG


def verify_attestation(attest_token: str, nonce: bytes, platform: Literal["android", "ios"]) -> bool:
    """
    Verify attestation using Play Integrity (android) or App Attest (ios)

    Parameters:
        attest_token: JWT sent by app installation
        nonce: nonce used to encode the token
        platform: device's platform

    Returns:
        bool: True if verified, False if not
    """
    attestation = Attestation(
        attest_token,
        nonce,
        PLAY_INTEGRITY_CONFIG if platform == "android" else APP_ATTEST_CONFIG
    )

    try:
        attestation.verify()
        return True

    except PyAttestException:
        return False


def generate_device_jwt(uuid: str, platform: Literal["android", "ios"]) -> tuple[str, str]:
    """
    Generate JWT access and refresh token pair for a device

    Parameters:
        uuid: UUID of the device
        platform: device's platform

    Returns:
        (str, str): access token, refresh token
    """

    refresh = RefreshToken()

    refresh['device_id'] = str(uuid)
    refresh['type'] = platform

    access = refresh.access_token
    return str(access), str(refresh)

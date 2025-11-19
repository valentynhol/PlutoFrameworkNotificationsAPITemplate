import secrets

from django.db import models
from django.utils import timezone
from fcm_django.models import AbstractFCMDevice
from django.utils.translation import gettext_lazy as _

from ApiCore.settings import ATTESTATION_NONCE_EXPIRY_SECONDS
from ApiApp import utils


class AttestedFCMDevice(AbstractFCMDevice):
    registration_id = models.TextField(verbose_name=_("Registration token"), unique=False, null=True)
    attest_nonce = models.CharField(verbose_name=_("Attest nonce"), max_length=255, null=True, blank=True)
    attest_nonce_created_at = models.DateTimeField(verbose_name=_("Attest nonce created at"), null=True, blank=True)

    class Meta:
        indexes = []
        verbose_name = "Attested FCM device"
        verbose_name_plural = "Attested FCM devices"

    def generate_nonce(self, length: int = 32) -> str:
        """
        Generate a cryptographically secure random nonce,
        store it in the device, and return it.
        """
        self.attest_nonce = secrets.token_urlsafe(length)
        self.attest_nonce_created_at = timezone.now()
        self.save(update_fields=["attest_nonce", "attest_nonce_created_at"])
        return self.attest_nonce

    def is_nonce_valid(self) -> bool:
        """
        Check if the nonce exists and is not expired.
        Expiry is controlled by NONCE_EXPIRY_SECONDS in settings.
        """
        if not self.attest_nonce or not self.attest_nonce_created_at:
            return False

        age = (timezone.now() - self.attest_nonce_created_at).total_seconds()
        return age <= ATTESTATION_NONCE_EXPIRY_SECONDS

    def clear_nonce(self):
        self.attest_nonce = None
        self.attest_nonce_created_at = None
        self.save(update_fields=["attest_nonce", "attest_nonce_created_at"])

    def verify_attestation(self, attest_token: str) -> bool:
        """
        Verify attestation for this device using its stored nonce.
        """
        if not self.is_nonce_valid():
            return False

        verified = utils.verify_attestation(attest_token, self.attest_nonce.encode(), self.type)

        if verified:
            self.clear_nonce()

        return verified

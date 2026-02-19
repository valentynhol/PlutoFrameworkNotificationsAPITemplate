from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from django.db import models
from django.utils import timezone
from fcm_django.models import AbstractFCMDevice
from django.utils.translation import gettext_lazy as _

from ApiApp.managers import NonceManager
from ApiCore.settings import ATTESTATION_NONCE_EXPIRY_SECONDS


class AttestedFCMDevice(AbstractFCMDevice):
    registration_id = models.TextField(verbose_name=_("Registration token"), unique=False, null=True)
    public_key_pem = models.BinaryField(verbose_name=_("Public key (iOS)"), null=True, blank=True)

    class Meta:
        indexes = []
        verbose_name = "Attested FCM device"
        verbose_name_plural = "Attested FCM devices"

    def set_public_key(self, public_key: EllipticCurvePublicKey):
        self.public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.save(update_fields=["public_key_pem"])

    def get_public_key(self):
        return serialization.load_der_public_key(self.public_key_pem)


class Nonce(models.Model):
    nonce = models.CharField(verbose_name=_("Nonce"), max_length=255, primary_key=True)
    created_at = models.DateTimeField(verbose_name=_("Nonce created at"), db_index=True)
    consumed = models.BooleanField(verbose_name=_("Consumed"), default=False)

    objects = NonceManager()

    class Meta:
        verbose_name = "Nonce"
        verbose_name_plural = "Nonces"

    def is_nonce_valid(self) -> bool:
        """
        Check whether the nonce is not consumed or expired.
        Expiration time is set by ATTESTATION_NONCE_EXPIRY_SECONDS in ApiCore.settings.
        """
        age = (timezone.now() - self.created_at).total_seconds()
        return not self.consumed and age <= ATTESTATION_NONCE_EXPIRY_SECONDS

    def consume(self) -> str:
        """
        Consume the nonce from the device.
        Returns:
             consumed nonce
        """
        self.consumed = True
        self.save(update_fields=["consumed"])
        return self.nonce

from datetime import timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from django.db import models
from django.utils import timezone
from fcm_django.models import AbstractFCMDevice
from django.utils.translation import gettext_lazy as _

from ApiApp.managers import NonceManager
from ApiCore.settings import ATTESTATION_NONCE_EXPIRY_SECONDS


class AttestedFCMDevice(AbstractFCMDevice):
    # What to identify the user with to then send notifications without using Firebase identifiers
    # (For example, you could use wallet address)
    uid = models.TextField(verbose_name=_("User identifier"), unique=False, null=True)

    registration_id = models.TextField(verbose_name=_("Registration token"), unique=False, null=True) # reset unique
    public_key_der = models.BinaryField(verbose_name=_("Public key (iOS)"), null=True, blank=True)

    class Meta:
        indexes = []
        verbose_name = "Attested FCM device"
        verbose_name_plural = "Attested FCM devices"

    def set_public_key(self, public_key: EllipticCurvePublicKey):
        self.public_key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.save(update_fields=["public_key_der"])

    def get_public_key(self):
        if self.public_key_der is None:
            return None

        return serialization.load_der_public_key(bytes(self.public_key_der))


class Nonce(models.Model):
    nonce = models.CharField(verbose_name=_("Nonce"), max_length=255, primary_key=True)
    created_at = models.DateTimeField(verbose_name=_("Nonce created at"), db_index=True)
    consumed = models.BooleanField(verbose_name=_("Consumed"), default=False)

    objects = NonceManager()

    class Meta:
        verbose_name = "Nonce"
        verbose_name_plural = "Nonces"

    def consume(self) -> bool:
        """
        Consume the nonce if valid.
        Returns:
             bool: True if the nonce is consumed, False otherwise.
        """
        cutoff = timezone.now() - timedelta(
            seconds=ATTESTATION_NONCE_EXPIRY_SECONDS
        )

        updated = (
            Nonce.objects
            .filter(
                nonce=self.nonce,
                consumed=False,
                created_at__gte=cutoff
            )
            .update(consumed=True)
        )

        if updated == 1:
            self.consumed = True
            return True

        return False

import secrets
from datetime import timedelta

from django.core.cache import cache
from django.db import models, transaction, IntegrityError
from django.utils import timezone

from ApiCore.settings import ATTESTATION_NONCE_EXPIRY_SECONDS, ATTESTATION_NONCE_CLEANUP_TIMEOUT_SECONDS

NONCE_CLEANUP_LOCK_KEY = "nonce_cleanup_lock"


class NonceManager(models.Manager):
    def create_nonce(self, length: int = 32) -> str:
        """
        Generate a cryptographically secure random nonce.
        Returns:
             generated nonce
        """
        for _ in range(5):
            nonce_value = secrets.token_urlsafe(length)
            try:
                with transaction.atomic():
                    obj = self.create(
                        nonce=nonce_value,
                        created_at=timezone.now(),
                        consumed=False
                    )
                return obj.nonce
            except IntegrityError:
                continue

        raise RuntimeError("Failed to generate unique nonce")

    def cleanup(self) -> int:
        """
        Delete any expired nonces.
        Returns:
            deleted records count
        """
        if cache.get(NONCE_CLEANUP_LOCK_KEY):
            return 0

        cache.set(NONCE_CLEANUP_LOCK_KEY, True, timeout=ATTESTATION_NONCE_CLEANUP_TIMEOUT_SECONDS)
        cutoff = timezone.now() - timedelta(seconds=ATTESTATION_NONCE_EXPIRY_SECONDS)
        return self.filter(created_at__lt=cutoff).delete()[0]

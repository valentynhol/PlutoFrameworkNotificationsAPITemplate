import secrets

from django.db import models, transaction, IntegrityError
from django.utils import timezone


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

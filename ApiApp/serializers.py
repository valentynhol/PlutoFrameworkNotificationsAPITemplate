import logging
from rest_framework import serializers

from ApiApp.models import AttestedFCMDevice, Nonce
from ApiApp.utils import generate_device_jwt, AttestationHandler

logger = logging.getLogger(__name__)


class FCMTokenSerializer(serializers.Serializer):
    fcm_token = serializers.CharField(max_length=255)


class UidSerializer(serializers.Serializer):
    user_id = serializers.CharField(max_length=255)


class NotificationPayloadSerializer(serializers.Serializer):
    user_id = serializers.CharField(max_length=255, required=True)
    title = serializers.CharField(max_length=150, required=True)
    body = serializers.CharField(max_length=500, required=True)


class DeviceRegisterSerializer(serializers.Serializer):
    nonce = serializers.CharField(max_length=255)
    device_id = serializers.CharField(max_length=255)
    platform = serializers.ChoiceField(choices=['android', 'ios'])
    attestation = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    assertion = serializers.CharField(required=False, allow_null=True, allow_blank=True)

    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)

    def validate(self, attrs):
        logger.debug("DeviceRegisterSerializer.validate called")
        logger.debug(f"Incoming attrs keys: {list(attrs.keys())}")

        nonce = attrs.get('nonce')
        device_id = attrs.get("device_id")
        platform = attrs.get("platform")
        attestation = attrs.get("attestation")
        assertion = attrs.get("assertion")

        logger.debug(f"nonce={nonce}")
        logger.debug(f"device_id={device_id}")
        logger.debug(f"platform={platform}")
        logger.debug(f"has_attestation={bool(attestation)}")
        logger.debug(f"has_assertion={bool(assertion)}")

        try:
            nonce_record = Nonce.objects.get(nonce=nonce)
            logger.debug("Nonce record found")

            if not nonce_record.consume():
                logger.debug("Nonce is not valid")
                raise serializers.ValidationError("Nonce is not valid.")

        except Nonce.DoesNotExist:
            logger.debug("Nonce does not exist in DB")
            raise serializers.ValidationError("Nonce does not exist.")

        public_key = None
        try:
            device = AttestedFCMDevice.objects.get(device_id=device_id, type=platform)
            public_key = device.get_public_key()
            logger.debug("Existing device found, public key loaded")
        except AttestedFCMDevice.DoesNotExist:
            logger.debug("No existing device found")

        try:
            logger.debug("Initializing AttestationHandler")
            handler = AttestationHandler(nonce, platform, attestation, assertion, device_id, public_key)
        except Exception as e:
            logger.exception("AttestationHandler init failed")
            raise serializers.ValidationError(f"Handler init failed: {str(e)}")

        try:
            logger.debug("Starting multiplatform_verify")
            verified = handler.multiplatform_verify()
            logger.debug(f"Verification result: {verified}")

            if not verified:
                raise serializers.ValidationError("Attestation verification failed.")

        except Exception as e:
            logger.exception("Verification threw exception")
            raise serializers.ValidationError(f"Verification error: {str(e)}")

        if platform == 'ios' and public_key is None:
            logger.debug("Creating new iOS device record with public key")
            device = AttestedFCMDevice.objects.create(
                device_id=device_id,
                type=platform
            )
            device.set_public_key(handler.get_public_key())

        logger.debug("Validation successful")
        return attrs

    def create(self, validated_data):
        device_id = validated_data['device_id']
        platform = validated_data['platform']

        device, _ = AttestedFCMDevice.objects.update_or_create(
            device_id=device_id,
            defaults={
                "type": platform,
            }
        )

        access, refresh = generate_device_jwt(device_id, platform)

        return {
            "access": str(access),
            "refresh": str(refresh)
        }

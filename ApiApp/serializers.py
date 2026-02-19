from rest_framework import serializers

from ApiApp.models import AttestedFCMDevice, Nonce
from ApiApp.utils import generate_device_jwt, AttestationHandler


class FCMTokenSerializer(serializers.Serializer):
    fcm_token = serializers.CharField(max_length=255)


class DeviceRegisterSerializer(serializers.Serializer):
    nonce = serializers.CharField(max_length=255)
    device_id = serializers.CharField(max_length=255)
    platform = serializers.ChoiceField(choices=['android', 'ios'])
    attestation = serializers.CharField(required=False)
    assertion = serializers.CharField(required=False)

    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)

    def validate(self, attrs):
        nonce = attrs.get('nonce')
        device_id = attrs.get("device_id")
        platform = attrs.get("platform")
        attestation = attrs.get("attestation")
        assertion = attrs.get("assertion")

        try:
            nonce_record = Nonce.objects.get(nonce=nonce)

            if not nonce_record.is_valid():
                raise serializers.ValidationError("Nonce is not valid.")
        except Nonce.DoesNotExist:
            raise serializers.ValidationError("Nonce does not exist.")

        public_key = None
        try:
            device = AttestedFCMDevice.objects.get(device_id=device_id, type=platform)
            public_key = device.get_public_key()
        except AttestedFCMDevice.DoesNotExist:
            pass

        handler = AttestationHandler(nonce, platform, attestation, assertion, device_id, public_key)
        if not handler.multiplatform_verify():
            raise serializers.ValidationError("Attestation verification failed.")

        if platform == 'ios' and public_key is None:
            device = AttestedFCMDevice.objects.create(
                device_id=device_id,
                type=platform
            )
            device.set_public_key(handler.get_public_key())

        nonce_record.consume()

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

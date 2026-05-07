import logging

from firebase_admin import messaging
from rest_framework import permissions, views, status
from rest_framework.response import Response
from rest_framework_api_key.permissions import HasAPIKey

from ApiApp.serializers import (DeviceRegisterSerializer, FCMTokenSerializer, UidSerializer,
                                NotificationPayloadSerializer)
from ApiApp.auth import DeviceJWTAuthentication
from ApiApp.permissions import IsRegisteredDevice
from ApiApp.models import AttestedFCMDevice, Nonce

logger = logging.getLogger(__name__)


class NonceView(views.APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, _):
        deleted = Nonce.objects.cleanup()
        logger.debug(f"Deleted {deleted} nonce records.")
        nonce = Nonce.objects.create_nonce()

        return Response({"nonce": nonce})


class DeviceRegisterView(views.APIView):
    permission_classes = [permissions.AllowAny]

    serializer_class = DeviceRegisterSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        tokens = serializer.save() # serializer returns JWT pair after saving the device instance

        return Response(tokens)


class FCMTokenUpdateView(views.APIView):
    permission_classes = [IsRegisteredDevice]
    authentication_classes = [DeviceJWTAuthentication]

    serializer_class = FCMTokenSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        fcm_token = serializer.validated_data['fcm_token']

        try:
            device = AttestedFCMDevice.objects.get(device_id=request.device_id)
        except AttestedFCMDevice.DoesNotExist:
            # shouldn't happen
            return Response({'detail': 'Device not found.'}, status=status.HTTP_404_NOT_FOUND)

        device.registration_id = fcm_token
        device.save(update_fields=['registration_id'])

        # Subscribe to necessary FCM topics
        topics = ['global', device.type]
        for topic in topics:
            try:
                messaging.subscribe_to_topic([device.registration_id], topic)
            except Exception as e:
                logger.debug(f'Failed to subscribe device {device.id} to topic {topic}: {e}')

        return Response({'message': 'Token updated successfully.'}, status=status.HTTP_200_OK)


class UidUpdateView(views.APIView):
    permission_classes = [IsRegisteredDevice]
    authentication_classes = [DeviceJWTAuthentication]

    serializer_class = UidSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        uid = serializer.validated_data['user_id']

        try:
            device = AttestedFCMDevice.objects.get(device_id=request.device_id)
        except AttestedFCMDevice.DoesNotExist:
            # shouldn't happen
            return Response({'detail': 'Device not found.'}, status=status.HTTP_404_NOT_FOUND)

        device.uid = uid
        device.save(update_fields=['uid'])

        return Response({'message': 'User identifier updated successfully.'}, status=status.HTTP_200_OK)


class SendNotificationView(views.APIView):
    permission_classes = [HasAPIKey]

    serializer_class = NotificationPayloadSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_id = serializer.validated_data['user_id']
        title = serializer.validated_data['title']
        body = serializer.validated_data['body']

        devices = AttestedFCMDevice.objects.filter(user_id=user_id).exclude(registration_id__isnull=True)

        if not devices.exists():
            return Response(
                {'detail': 'No registered devices found for this user.'},
                status=status.HTTP_404_NOT_FOUND
            )

        message = messaging.Message(
            notification=messaging.Notification(
                title=title,
                body=body,
            ),
        )

        success_count = 0
        failure_count = 0
        for device in devices:
            try:
                device.send_message(message)
                success_count += 1
            except Exception as e:
                logger.error(f'Error sending message to device {device.id}: {e}')
                failure_count += 1

        return Response(
            {
                'message': 'Notification process completed.',
                'success_count': success_count,
                'failure_count': failure_count,
            },
            status=status.HTTP_200_OK
        )
import logging

from firebase_admin import messaging
from rest_framework import permissions, views, status
from rest_framework.response import Response

from ApiApp.serializers import DeviceRegisterSerializer, FCMTokenSerializer, UidSerializer
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

        if serializer.is_valid():
            fcm_token = serializer.validated_data['fcm_token']

            try:
                device = AttestedFCMDevice.objects.get(device_id=request.device_id)
            except AttestedFCMDevice.DoesNotExist:
                # shouldn't happen
                return Response({'error': 'Device not found.'}, status=status.HTTP_404_NOT_FOUND)

            device.registration_id = fcm_token
            device.save(update_fields=['registration_id'])

            # Subscribe to necessary FCM topics
            topics = ["global", device.type]
            for topic in topics:
                try:
                    messaging.subscribe_to_topic([device.registration_id], topic)
                except Exception as e:
                    print(f"Failed to subscribe device {device.id} to topic {topic}: {e}")

            return Response({'message': 'Token updated successfully.'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UidUpdateView(views.APIView):
    permission_classes = [IsRegisteredDevice]
    authentication_classes = [DeviceJWTAuthentication]

    serializer_class = UidSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            uid = serializer.validated_data['user_id']

            try:
                device = AttestedFCMDevice.objects.get(device_id=request.device_id)
            except AttestedFCMDevice.DoesNotExist:
                # shouldn't happen
                return Response({'error': 'Device not found.'}, status=status.HTTP_404_NOT_FOUND)

            device.user_id = uid
            device.save(update_fields=['user_id'])

            return Response({'message': 'User identifier updated successfully.'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# TODO
class SendNotification(views.APIView):
    pass
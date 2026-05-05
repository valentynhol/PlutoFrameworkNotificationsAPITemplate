from rest_framework_simplejwt.authentication import JWTAuthentication

class DeviceJWTAuthentication(JWTAuthentication):
    def get_user(self, validated_token):
        return None

    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)
        request.device_id = validated_token.get('device_id')
        return None, validated_token
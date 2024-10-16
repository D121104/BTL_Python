from django.utils.deprecation import MiddlewareMixin
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.http import JsonResponse

class JWTAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        access_token = request.session.get('access_token')
        refresh_token = request.session.get('refresh_token')
        
        if access_token:
            try:
                # Kiểm tra tính hợp lệ của access_token
                AccessToken(access_token)
                request.META['HTTP_AUTHORIZATION'] = f'Bearer {access_token}'
            except TokenError:
                # Nếu access_token hết hạn, làm mới nó bằng refresh_token
                if refresh_token:
                    try:
                        refresh = RefreshToken(refresh_token)
                        new_access_token = str(refresh.access_token)
                        request.session['access_token'] = new_access_token
                        request.META['HTTP_AUTHORIZATION'] = f'Bearer {new_access_token}'
                    except TokenError:
                        return JsonResponse({'detail': 'Token is invalid or expired'}, status=403)
                else:
                    return JsonResponse({'detail': 'Token is invalid or expired'}, status=403)
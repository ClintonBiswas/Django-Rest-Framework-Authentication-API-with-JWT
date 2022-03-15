from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from account.serializers import UserChangePasswordSerializer, UserLoginSerializer, UserPasswordResetSerializer, UserProfileSerializer,UserRegistationSerializer, UserResetPassworsSerializer
from account.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

# Generate Token Manually

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

# Create your views here.
# Register View
class UserRegistrationView(APIView):
    #renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = UserRegistationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({'token':token,'msg': 'Registration Successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#Login View
class UserLoginView(APIView):
    #renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password=password)
            if user is not None:
                token = get_tokens_for_user(user)
                return Response({'token':token,'msg': 'Login succesfull'}, status=status.HTTP_200_OK)
            else:
                return Response({'errors':{'non_field_errors':['Email or password is not valid']}}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# User Profile
class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        
        return Response(serializer.data, status=status.HTTP_200_OK)

# Change Password View
class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(data=request.data, context={'user': request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': 'Password Changed Successfull'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Send Reset Password Email

class UserRestPasswordView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = UserResetPassworsSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': 'Password Reset Link Send. Please Check Your email.'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Send Email For Password Reset
class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
        serializer.is_valid(raise_exception=True)
        return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)
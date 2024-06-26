from django.core.mail import send_mail
from rest_framework import viewsets, generics, status, permissions
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import *
from django.contrib.auth import authenticate
from .models import CustomUser
from django.contrib.auth import logout
from django.http import JsonResponse


class CustomUserListCreateAPIView(generics.ListCreateAPIView):
    permission_classes = [AllowAny]
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer


class CustomUserRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [AllowAny]
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer


class SalarySlipViewSet(viewsets.ModelViewSet):
    queryset = SalarySlip.objects.all()
    permission_classes = [AllowAny]
    serializer_class = SalarySlipSerializer

    def get_queryset(self):
        # Filter slips based on the requesting user
        user = self.request.user  # Get the currently authenticated user
        if user.is_staff:  # Assuming staff can see all salary slips
            return SalarySlip.objects.all().order_by('-upload_date')
        return SalarySlip.objects.filter(user=user).order_by('-upload_date')

class NotificationViewSet(viewsets.ModelViewSet):
    permission_classes = [AllowAny]
    queryset = Notification.objects.all()
    serializer_class = NotificationSerializer

class LeaveRequestViewSet(viewsets.ModelViewSet):
    serializer_class = LeaveRequestSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        user = self.request.user
        return LeaveRequest.objects.filter(employee=user).order_by('-start_date')

    def perform_create(self, serializer):
        serializer.save(employee=self.request.user)

class AdminLeaveRequestViewSet(viewsets.ModelViewSet):
    serializer_class = LeaveRequestSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        return LeaveRequest.objects.all().order_by('-start_date')

    def perform_update(self, serializer):
        user = self.request.user
        if hasattr(user, 'role') and user.role == 'admin':
            serializer.save(status=serializer.validated_data['status'])




class UserLoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        data = request.data
        username = data.get('username')
        password = data.get('password')

        user = authenticate(request, username=username, password=password)
        if user is not None:

            refresh = RefreshToken.for_user(user)
            refresh_token = str(refresh)

            profile_photo_url = None
            if user.profile_photo:
                profile_photo_url = request.build_absolute_uri(user.profile_photo.url)

            return Response({
                'access': str(refresh.access_token),
                'refresh': refresh_token,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'designation': user.designation,
                    'role': user.role,
                    'email': user.email,
                    'profile_photo_url': profile_photo_url,
                    'active_status': user.is_active

                }
            })
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)

class UserRegisterAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'User created successfully.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLogoutAPIView(APIView):
    def post(self, request):
        if request.method == 'POST':
            logout(request)
            return JsonResponse({'message': 'User logged out successfully.'})
        else:
            return JsonResponse({'error': 'Method not allowed.'}, status=405)


class ContactView(APIView):
    permission_classes = [AllowAny]
    def post(self, request, *args, **kwargs):
        serializer = ContactSerializer(data=request.data)
        if serializer.is_valid():
            name = serializer.validated_data['name']
            email = serializer.validated_data['email']
            phoneno = str(serializer.validated_data['phoneno'])
            message = serializer.validated_data['message']

            # Create the full message
            full_message = f"Name: {name}\nPhone: {phoneno}\nMessage: {message}"

            try:
                # Send the message to your email
                send_mail(
                    'New Contact Form Submission',
                    full_message,
                    'shazil03144426622@gmail.com',
                    ['shazil03144426622@gmail.com'],
                    fail_silently=False,
                )

                # Send a thank you message to the user
                send_mail(
                    'Thank you for contacting us',
                    f'Thank you for reaching out, {name}!\n\nWe have received your message and will get back to you soon.',
                    'shazil03144426622@gmail.com',
                    [email],
                    fail_silently=False,
                )

                return Response({'message': 'Message sent successfully!'}, status=status.HTTP_200_OK)
            except Exception as e:
                print(f"An error occurred: {e}")
                return Response({'error': 'Failed to send message'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
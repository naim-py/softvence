from rest_framework.views import APIView
from rest_framework.generics import RetrieveUpdateDestroyAPIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .models import Employer
from .serializers import EmployerSerializer
from .permissions import IsEmployerOwner

class EmployerListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """List all employers for the authenticated user."""
        employers = Employer.objects.filter(user=request.user)
        serializer = EmployerSerializer(employers, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        """Create a new employer for the authenticated user."""
        serializer = EmployerSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class EmployerDetailView(RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated, IsEmployerOwner]
    serializer_class = EmployerSerializer
    lookup_field = 'pk'

    def get_queryset(self):
        """Return employers for the authenticated user only."""
        return Employer.objects.filter(user=self.request.user)

    def get(self, request, *args, **kwargs):
        """Retrieve a specific employer."""
        return super().get(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        """Update a specific employer."""
        return super().put(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        """Delete a specific employer."""
        return super().delete(request, *args, **kwargs)
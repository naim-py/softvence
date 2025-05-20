from django.urls import path
from .views import EmployerListCreateView, EmployerDetailView

app_name = 'employers'

urlpatterns = [
    path('employers/', EmployerListCreateView.as_view(), name='employer-list-create'),
    path('<int:pk>/', EmployerDetailView.as_view(), name='employer-detail'),
]
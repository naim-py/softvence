from django.contrib import admin
from .models import Employer

@admin.register(Employer)
class EmployerAdmin(admin.ModelAdmin):
    list_display = ('company_name', 'email', 'contact_person_name', 'user', 'created_at')
    list_filter = ('user', 'created_at')
    search_fields = ('company_name', 'email', 'contact_person_name')
    readonly_fields = ('created_at',)
    fieldsets = (
        (None, {
            'fields': ('user', 'company_name', 'contact_person_name', 'email', 'phone_number', 'address')
        }),
        ('Metadata', {
            'fields': ('created_at',)
        }),
    )
    ordering = ('-created_at',)
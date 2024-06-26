from django.contrib import admin
from .models import CustomUser, SalarySlip, Notification, LeaveRequest

# Register your models here.
admin.site.register(CustomUser)
admin.site.register(SalarySlip)
admin.site.register(Notification)
admin.site.register(LeaveRequest)

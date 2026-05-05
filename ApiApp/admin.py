from django.contrib import admin

from fcm_django.models import FCMDevice
from .models import AttestedFCMDevice


admin.site.unregister(FCMDevice)

@admin.register(AttestedFCMDevice)
class AttestedFCMDeviceAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "uid",
        "name",
        "type",
        "device_id",
        "registration_id",
        "active",
        "date_created",
    )
    list_filter = ("type", "active")
    search_fields = ("name", "registration_id")

from django.contrib import admin
from . models import Profile

# Register your models here.

class ProfileAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'user', 'phone', 'image'
    )
admin.site.register(Profile, ProfileAdmin)
from django.contrib import admin
from main.models import About

# Register your models here.


class AboutAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'title', 'description', 'mission', 'vision'
    )
admin.site.register(About, AboutAdmin)
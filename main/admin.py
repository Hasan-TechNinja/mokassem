from django.contrib import admin
from main.models import About, SearchHistory

# Register your models here.


class AboutAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'title', 'description', 'mission', 'vision'
    )
admin.site.register(About, AboutAdmin)


class SearchHistoryAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'user', 'text', 'created_at'
    )
admin.site.register(SearchHistory, SearchHistoryAdmin)
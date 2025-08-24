from django.db import models
from django.contrib.auth.models import User
from ckeditor.fields import RichTextField

# Create your models here.

class About(models.Model):
    title = models.CharField(max_length=300)
    description = models.CharField(max_length=500)
    mission = models.TextField()
    vision = models.TextField()
    
    def __str__(self):
        return self.title
    

class SearchHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, db_index=True, related_name="search_histories")
    text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]  # newest first

    def __str__(self):
        preview = (self.text or "")[:20]
        suffix = "..." if len(self.text or "") > 20 else ""
        return f"{self.user.username} searched: {preview}{suffix}"

class SearchResult(models.Model):
    user = models.ForeignKey(User, on_delete= models.CASCADE)
    message = RichTextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username}'s searched result: {self.message[:20]}"
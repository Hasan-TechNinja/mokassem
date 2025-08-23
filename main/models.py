from django.db import models

# Create your models here.

class About(models.Model):
    title = models.CharField(max_length=300)
    description = models.CharField(max_length=500)
    mission = models.TextField()
    vision = models.TextField()
    
    def __str__(self):
        return self.title
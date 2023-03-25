from django.db import models

class User(models.Model):
    username = models.CharField(max_length=50)
    email = models.EmailField(max_length=254)
    usr_password = models.CharField(max_length=255)
    age = models.IntegerField()
    weight = models.DecimalField(max_digits=5, decimal_places=2)
    height = models.DecimalField(max_digits=5, decimal_places=2)
    sex = models.CharField(max_length=10, choices=[('male', 'Male'), ('female', 'Female')])
    activity_level = models.CharField(max_length=50)
    img_url = models.CharField(max_length=1000)


# username = "SeniorDeveloper"
# password = "134697825/*-qweQWE"
# ip = "87.246.193.76"
# hostname = "food-app-server.mysql.database.azure.com"
# ssl_mode = "require"
# database = "FoodTracker"
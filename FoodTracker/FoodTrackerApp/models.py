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

    class Meta:
        db_table = 'users'


class Frige(models.Model):
    product_id = models.IntegerField()
    user_id = models.IntegerField()
    location = models.CharField(max_length = 100)
    expire_data = models.DateField()
    weight = models.DecimalField(max_digits=5, decimal_places=2)
    how_much = models.DecimalField(max_digits=5, decimal_places=2)
    


class Product(models.Model):
    user_id = models.IntegerField()
    product_name = models.CharField(max_length = 100)
    calories = models.DecimalField(max_digits=5, decimal_places=2)
    protein = models.DecimalField(max_digits=5, decimal_places=2)
    fat = models.DecimalField(max_digits=5, decimal_places=2)
    carbohydrates = models.DecimalField(max_digits=5, decimal_places=2)
    barcode = models.CharField(max_length=1000)
    img_url = models.CharField(max_length=1000)



class Recipe(models.Model):
    user_id = models.IntegerField()
    name = models.CharField(max_length = 100)
    annotation = models.CharField(max_length = 100)
    recepe_text = models.CharField(max_length = 100)
    rate = models.DecimalField(max_digits=5, decimal_places=2)
    img_url = models.CharField(max_length=1000)
    


class RecipesProducts(models.Model):
    product_id = models.IntegerField()
    recipe_id = models.IntegerField()
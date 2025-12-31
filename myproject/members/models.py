from django.db import models
from django.core.validators import MinLengthValidator, RegexValidator

class Role(models.Model):
    ROLE_MEMBER = 'member'
    ROLE_HEAD = 'head'
    ROLE_SECRETARIAT = 'secretariat'
    ROLE_ADMIN = 'admin'

    ROLE_CHOICES = [
        (ROLE_MEMBER, 'Member'),
        (ROLE_HEAD, 'Head'),
        (ROLE_SECRETARIAT, 'Secretariat'),
        (ROLE_ADMIN, 'Admin'),
    ]

    name = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        unique=True
    )

    def __str__(self):
        return self.get_name_display()


class Department(models.Model):
    name = models.CharField(max_length=255, unique=True)

    heads = models.ManyToManyField(
        'Member',
        blank=True,
        related_name='headed_departments'
    )

    def __str__(self):
        return self.name


class Member(models.Model):
    firstname = models.CharField(max_length=255)
    lastname = models.CharField(max_length=255)

    phone = models.CharField(
        max_length=10,
        validators=[RegexValidator(r'^\d{10}$', "Phone number must be exactly 10 digits")],
        null=True,
        blank=True
    )

    joined_date = models.DateField(null=True, blank=True)
    username = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255, validators=[MinLengthValidator(5)])
    email = models.CharField(max_length=255, unique=True, null=True, blank=True)

    departments = models.ManyToManyField(Department, blank=True)

    role = models.ForeignKey(
        Role,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    profile_photo = models.ImageField(
        upload_to='profile_photos/',
        null=True,
        blank=True
    )

    def __str__(self):
        return f"{self.firstname} {self.lastname}"

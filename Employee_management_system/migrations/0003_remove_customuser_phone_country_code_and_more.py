# Generated by Django 5.0.4 on 2024-04-25 08:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Employee_management_system', '0002_alter_customuser_id'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customuser',
            name='phone_country_code',
        ),
        migrations.AlterField(
            model_name='customuser',
            name='phone_number',
            field=models.CharField(blank=True, max_length=15, null=True),
        ),
    ]

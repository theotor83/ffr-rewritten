# Generated by Django 5.1.6 on 2025-03-18 19:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('forum', '0042_populate_database'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='desc',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
    ]

# Generated by Django 5.1.6 on 2025-03-01 22:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('forum', '0023_topic_last_message_time'),
    ]

    operations = [
        migrations.AlterField(
            model_name='topic',
            name='last_message_time',
            field=models.DateTimeField(auto_now_add=True),
        ),
    ]

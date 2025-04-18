# Generated by Django 5.1.6 on 2025-02-26 19:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('forum', '0001_initial'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='Group',
            new_name='ForumGroup',
        ),
        migrations.AlterField(
            model_name='profile',
            name='zodiac_sign',
            field=models.CharField(blank=True, choices=[('capricorne', 'Capricorne (22déc-19jan)'), ('verseau', 'Verseau (20jan-19fev)'), ('poissons', 'Poissons(20fev-20mar)'), ('belier', 'Bélier (21mar-19avr)'), ('taureau', 'Taureau(20avr-20mai)'), ('gemeaux', 'Gémeaux (21mai-20juin)'), ('Cancer', 'Cancer (21juin-23juil)'), ('lion', 'Lion (24juil-23aoû)'), ('vierge', 'Vierge (24aoû-22sep)'), ('balance', 'Balance (23sep-22oct)'), ('scorpion', 'Scorpion (23oct-21nov)'), ('sagittaire', 'Sagittaire (22nov-21déc)'), ('', 'Aucun')], max_length=20, null=True),
        ),
    ]

# Generated by Django 2.1.3 on 2020-12-26 02:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authenticate', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Account',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user', models.CharField(max_length=11)),
                ('avatar', models.ImageField(upload_to='avatar')),
                ('balance', models.FloatField()),
                ('cost', models.FloatField()),
                ('regtime', models.DateField(auto_now_add=True)),
            ],
        ),
    ]

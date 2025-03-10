from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('influencers', '0001_initial'),  # Replace with your last migration
    ]

    operations = [
        migrations.AddField(
            model_name='influencer',
            name='social_platforms',
            field=models.JSONField(blank=True, default=list, null=True),
        ),
    ] 
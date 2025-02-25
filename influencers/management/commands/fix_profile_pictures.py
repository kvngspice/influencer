from django.core.management.base import BaseCommand
from influencers.models import Influencer
import os

class Command(BaseCommand):
    help = 'Fix profile picture paths in database'

    def handle(self, *args, **kwargs):
        influencers = Influencer.objects.all()
        for influencer in influencers:
            if influencer.profile_picture:
                # Get the filename
                old_path = influencer.profile_picture.name
                filename = os.path.basename(old_path)
                # Create new path
                new_path = f'influencer_profiles/{influencer.id}/{filename}'
                # Update the path
                influencer.profile_picture.name = new_path
                influencer.save()
                self.stdout.write(f'Updated {influencer.name}: {old_path} -> {new_path}') 
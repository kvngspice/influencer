from rest_framework import generics
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from .models import Campaign, Influencer, Booking, InfluencerNotification, Payment
from .serializers import CampaignSerializer, InfluencerSerializer, BookingSerializer
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes, parser_classes
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .utils import admin_required 
from django.contrib.auth import authenticate
from django.db.models import Q
from rest_framework import status
from django.contrib.auth.models import User
from influencers.models import Profile
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework_simplejwt.authentication import JWTAuthentication
import traceback
import json
from datetime import datetime, timedelta
import pandas as pd
import re


# ✅ Create and Retrieve Bookings
class BookingListCreateView(generics.ListCreateAPIView):
    queryset = Booking.objects.all().order_by('-created_at')
    serializer_class = BookingSerializer
    
    def get_queryset(self):
        return Booking.objects.all().order_by('-created_at')



class CampaignDetailView(generics.RetrieveAPIView):
    queryset = Campaign.objects.all()
    serializer_class = CampaignSerializer

    def get(self, request, *args, **kwargs):
        campaign = self.get_object()
        return Response({
            "id": campaign.id,
            "name": campaign.name,
            "objective": campaign.objective,
            "platforms": campaign.platforms,
            "budget": campaign.budget,
            "demography": campaign.demography,
            "gender": campaign.gender,
            "region": campaign.region,
            "industry": campaign.industry,
            "status": "Active" if campaign.active else "Inactive"  # 🟢 Return Active/Inactive status
        })
    
class CampaignListCreateView(generics.ListCreateAPIView):
    serializer_class = CampaignSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get_queryset(self):
        print(f"User making request: {self.request.user}")  # Debug log
        print(f"Auth header: {self.request.META.get('HTTP_AUTHORIZATION')}")  # Debug log
        return Campaign.objects.filter(owner=self.request.user)

    def list(self, request, *args, **kwargs):
        try:
            if not request.user.is_authenticated:
                return Response(
                    {'detail': 'Authentication credentials were not provided.'}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            queryset = self.get_queryset()
            print(f"Found {queryset.count()} campaigns for user")  # Debug log
            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)
        except Exception as e:
            print(f"Error in campaign list: {str(e)}")  # Debug log
            return Response(
                {'detail': f'Error fetching campaigns: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

    def create(self, request, *args, **kwargs):
        try:
            print("Received campaign data:", request.data)  # Debug print
            # Add the owner to the data before validation
            data = request.data.copy()
            data['owner'] = request.user.id
            
            serializer = self.get_serializer(data=data)
            if not serializer.is_valid():
                print("Validation errors:", serializer.errors)  # Debug print
                return Response({
                    'error': 'Invalid data',
                    'details': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
                
            campaign = serializer.save(owner=request.user)  # Associate campaign with user
            print("Campaign created successfully:", campaign)  # Debug print
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            print(f"Error creating campaign: {str(e)}")  # Debug print
            return Response({
                'error': 'Failed to create campaign',
                'details': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)



from django.http import JsonResponse
from rest_framework.decorators import api_view
from influencers.models import Influencer  # Adjust import based on your models

@api_view(['POST'])
def login_view(request):
    try:
        username = request.data.get('username')
        password = request.data.get('password')
        role = request.data.get('role')

        if not all([username, password, role]):
            return Response({
                'error': 'Please provide username, password and role'
            }, status=400)
        
        user = authenticate(username=username, password=password)
                
        if user is not None:
            try:
                # Get user profile
                profile = Profile.objects.get(user=user)
                
                # Check if user is trying to log in with the correct role
                if profile.role != role:
                    return Response({
                        'error': f'This account is registered as a {profile.role}, not as a {role}'
                    }, status=403)
                
                refresh = RefreshToken.for_user(user)
                return Response({
                    'token': str(refresh.access_token),
                    'role': profile.role,
                    'username': user.username,
                    'message': 'Login successful'
                })
            except Profile.DoesNotExist:
                return Response({
                    'error': 'User profile not found'
                }, status=404)
        else:
            return Response({
                'error': 'Invalid credentials'
            }, status=401)
    except Exception as e:
        return Response({
            'error': f'Server error: {str(e)}'
        }, status=500)

@api_view(["GET"])
def search_influencers(request, campaign_id):
    try:
        # Fetch influencers that match the campaign criteria (dummy filter for now)
        influencers = Influencer.objects.filter(platform="Instagram")  # Adjust based on logic

        # Convert to JSON-friendly format
        influencer_list = list(influencers.values("id", "name", "platform", "niche", "followers_count"))

        return JsonResponse(influencer_list, safe=False)  # ✅ Ensure JSON response

    except Exception as e:
        print("❌ ERROR:", str(e))  # Debugging
        return JsonResponse({"error": str(e)}, status=500)  # ✅ Return error JSON instead of None

    # Ensure platforms are stored as a list
    import json
    try:
        if isinstance(campaign.platforms, str):
            campaign_platforms = json.loads(campaign.platforms)
        elif isinstance(campaign.platforms, list):
            campaign_platforms = campaign.platforms
        else:
            campaign_platforms = []
    except json.JSONDecodeError:
        campaign_platforms = []

from rest_framework import generics
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .models import Booking
from .serializers import BookingSerializer

# ✅ Create and Retrieve Bookings
class BookingListCreateView(generics.ListCreateAPIView):
    queryset = Booking.objects.all().order_by('-created_at')  # Show recent bookings first
    serializer_class = BookingSerializer

@login_required
@admin_required
def admin_dashboard(request):
    return JsonResponse({"message": "Welcome, Admin!"})

@api_view(["POST"])
def book_influencer(request):
    try:
        data = request.data
        campaign_id = data.get("campaign")
        influencer_id = data.get("influencer")

        # ✅ Get campaign and influencer
        campaign = Campaign.objects.get(id=campaign_id)
        influencer = Influencer.objects.get(id=influencer_id)

        # ✅ Create a new booking entry
        booking = Booking.objects.create(campaign=campaign, influencer=influencer)

        # ✅ Return JSON response with influencer name and campaign details
        return JsonResponse({
            "message": "Influencer booked successfully!",
            "influencer_name": influencer.name,
            "campaign_name": campaign.name,
            "status": booking.status,
            "created_at": booking.created_at,
            "influencer": influencer.id,
            "campaign": campaign.id
        })

    except Exception as e:
        print("❌ ERROR:", str(e))  # Debugging
        return JsonResponse({"error": str(e)}, status=500)

@api_view(['PATCH'])
def update_booking_status(request, booking_id):
    try:
        booking = Booking.objects.get(pk=booking_id)
        new_status = request.data.get('status')
        
        if new_status not in ['approved', 'rejected', 'pending', 'completed']:
            return Response(
                {'error': 'Invalid status'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        booking.status = new_status
        booking.save()

        # If booking is approved, create a notification
        if new_status == 'approved' and booking.campaign.owner:
            InfluencerNotification.objects.create(
                influencer=booking.influencer,
                message=f"Your booking for campaign '{booking.campaign.name}' has been approved. Please proceed with payment."
            )
            print(f"Created notification for booking {booking_id}")

        return Response({
            'message': f'Booking status updated to {new_status}',
            'booking_id': booking.id,
            'status': new_status
        })

    except Booking.DoesNotExist:
        return Response(
            {'error': 'Booking not found'}, 
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        print(f"Error updating booking status: {str(e)}")
        return Response(
            {'error': str(e)}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

# ✅ Confirm Booking
@api_view(["POST"])
def confirm_booking(request, booking_id):
    try:
        booking = Booking.objects.get(id=booking_id)
        booking.status = "confirmed"  # ✅ Change status to Confirmed
        booking.save()
        return Response({"message": "Booking confirmed successfully."}, status=200)
    except Booking.DoesNotExist:
        return Response({"error": "Booking not found."}, status=404)


    # Filtering influencers based on campaign criteria
    influencers = Influencer.objects.filter(
        platform__in=campaign.platforms,  # Matches campaign platforms
        niche__icontains=campaign.industry,  # Matches industry
        demography=campaign.demography, # Matches demography
        region=campaign.region,
        followers_count__gte=int(campaign.budget) // 10  # Example: Higher budget gets more popular influencers
    ).order_by("-followers_count") 

    serializer = InfluencerSerializer(influencers, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def get_notifications(request, influencer_id):
    notifications = InfluencerNotification.objects.filter(influencer_id=influencer_id, is_read=False)
    data = [{"id": n.id, "message": n.message, "created_at": n.created_at} for n in notifications]
    return Response(data)

def admin_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated or not request.user.is_staff:
            return JsonResponse({"error": "Admin access required"}, status=403)
        return view_func(request, *args, **kwargs)
    return _wrapped_view


class InfluencerDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Influencer.objects.all()
    serializer_class = InfluencerSerializer
    parser_classes = (MultiPartParser, FormParser)
    
class InfluencerListCreateView(generics.ListCreateAPIView):
    queryset = Influencer.objects.all()
    serializer_class = InfluencerSerializer

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.filter_queryset(self.get_queryset())
            
            # Use a simpler serialization approach to avoid user field issues
            data = []
            for influencer in queryset:
                item = {
                    'id': influencer.id,
                    'name': influencer.name,
                    'platform': influencer.platform,
                    'niche': influencer.niche,
                    'followers_count': influencer.followers_count,
                    'profile_picture': influencer.get_profile_picture(),
                    'social_media_handle': influencer.social_media_handle,
                    'region': influencer.region,
                    'base_fee': str(influencer.base_fee),
                    'instagram_url': influencer.instagram_url,
                    'tiktok_url': influencer.tiktok_url,
                    'youtube_url': influencer.youtube_url,
                    'twitter_url': influencer.twitter_url,
                    'social_links': influencer.get_social_links()
                }
                
                # Only add user info if the field exists and is not None
                try:
                    if hasattr(influencer, 'user') and influencer.user:
                        item['user_username'] = influencer.user.username
                except:
                    item['user_username'] = None
                
                data.append(item)
            
            return Response(data)
        except Exception as e:
            print(f"Error in InfluencerListCreateView: {str(e)}")
            return Response({'error': str(e)}, status=500)

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['request'] = self.request
        return context

    def create(self, request, *args, **kwargs):
        try:
            print("Received data:", request.data)  # Debug print
            serializer = self.get_serializer(data=request.data)
            
            if serializer.is_valid():
                instance = serializer.save()
                print("Created influencer:", instance)  # Debug print
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                print("Validation errors:", serializer.errors)  # Debug print
                return Response({
                    'error': 'Invalid data',
                    'details': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(f"Error creating influencer: {str(e)}")  # Debug print
            return Response({
                'error': 'Failed to create influencer',
                'details': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class CampaignDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Campaign.objects.all()
    serializer_class = CampaignSerializer

@api_view(['POST'])
def create_booking(request):
    try:
        # Get data from request
        campaign_id = request.data.get('campaign_id')
        influencer_id = request.data.get('influencer_id')
        
        # Create the booking
        booking = Booking.objects.create(
            campaign_id=campaign_id,
            influencer_id=influencer_id,
            status='pending'
        )
        
        # Return success response
        return Response({
            'message': 'Booking created successfully',
            'booking_id': booking.id
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        print(f"Error creating booking: {str(e)}")
        return Response({
            'error': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def campaign_matches(request, campaign_id):
    try:
        campaign = Campaign.objects.get(id=campaign_id)
        
        # Build query based on campaign criteria
        query = Q()
        
        # Match by platform
        if hasattr(campaign, 'platforms') and campaign.platforms:
            platforms = campaign.platforms if isinstance(campaign.platforms, list) else []
            query &= Q(platform__in=platforms)
        
        # Match by content category
        if hasattr(campaign, 'industry') and campaign.industry:
            query &= Q(niche__icontains=campaign.industry)
            
        # Add region matching
        if hasattr(campaign, 'region') and campaign.region:
            query &= Q(region__iexact=campaign.region)
        
        # Add demographics matching
        if hasattr(campaign, 'demography') and campaign.demography:
            query &= Q(demography__icontains=campaign.demography)
        
        # Get matching influencers
        matched_influencers = Influencer.objects.filter(query)
        
        # Serialize the data
        data = [{
            'id': influencer.id,
            'name': influencer.name,
            'platform': influencer.platform,
            'followers_count': influencer.followers_count,
            'profile_picture': influencer.profile_picture.url if influencer.profile_picture else None,
            'niche': influencer.niche,
            'social_media_handle': influencer.social_media_handle,
            'region': influencer.region,
            'instagram_url': influencer.instagram_url,
            'tiktok_url': influencer.tiktok_url,
            'youtube_url': influencer.youtube_url,
            'twitter_url': influencer.twitter_url,
        } for influencer in matched_influencers]
        
        return Response(data)
        
    except Campaign.DoesNotExist:
        return Response({'error': 'Campaign not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def influencer_profile(request, influencer_id):
    """
    Get a specific influencer's profile
    """
    try:
        influencer = Influencer.objects.get(pk=influencer_id)
        
        # Use a simpler approach to avoid serialization issues
        data = {
            'id': influencer.id,
            'name': influencer.name,
            'platform': influencer.platform,
            'niche': influencer.niche,
            'followers_count': influencer.followers_count,
            'social_media_handle': influencer.social_media_handle if hasattr(influencer, 'social_media_handle') else '',
            'region': influencer.region if hasattr(influencer, 'region') else '',
            'interests': influencer.interests if hasattr(influencer, 'interests') else '',
            'bio': influencer.bio if hasattr(influencer, 'bio') else '',
            'engagement_rate': influencer.engagement_rate if hasattr(influencer, 'engagement_rate') else '',
            'content_categories': influencer.content_categories if hasattr(influencer, 'content_categories') else '',
            'demography': influencer.demography if hasattr(influencer, 'demography') else '',
            'base_fee': str(influencer.base_fee) if hasattr(influencer, 'base_fee') else '',
            'instagram_url': influencer.instagram_url if hasattr(influencer, 'instagram_url') else '',
            'tiktok_url': influencer.tiktok_url if hasattr(influencer, 'tiktok_url') else '',
            'youtube_url': influencer.youtube_url if hasattr(influencer, 'youtube_url') else '',
            'twitter_url': influencer.twitter_url if hasattr(influencer, 'twitter_url') else '',
        }
        
        # Add profile picture URL if it exists
        if hasattr(influencer, 'profile_picture') and influencer.profile_picture:
            data['profile_picture'] = request.build_absolute_uri(influencer.profile_picture.url)
        
        # Add social platforms if they exist
        if hasattr(influencer, 'social_platforms') and influencer.social_platforms:
            if isinstance(influencer.social_platforms, str):
                try:
                    data['social_platforms'] = json.loads(influencer.social_platforms)
                except:
                    data['social_platforms'] = []
            else:
                data['social_platforms'] = influencer.social_platforms
        
        return Response(data)
    except Influencer.DoesNotExist:
        return Response({
            'error': 'Influencer not found'
        }, status=404)
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=500)

class InfluencerUpdateView(generics.UpdateAPIView):
    queryset = Influencer.objects.all()
    serializer_class = InfluencerSerializer
    lookup_field = 'pk'

    def update(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            print("Received update data:", request.data)  # Debug print
            
            # Convert followers_count to integer if it's present
            if 'followers_count' in request.data:
                try:
                    request.data['followers_count'] = int(request.data['followers_count'])
                except (TypeError, ValueError):
                    return Response({
                        'error': 'Invalid followers count',
                        'details': 'Followers count must be a number'
                    }, status=status.HTTP_400_BAD_REQUEST)

            # Handle social_platforms if present
            social_platforms = request.data.get('social_platforms')
            print(f"Received social_platforms: {social_platforms}, type: {type(social_platforms)}")
            
            if social_platforms:
                # If it's a string, try to parse it as JSON
                if isinstance(social_platforms, str):
                    try:
                        # Try to parse the JSON string
                        social_platforms = json.loads(social_platforms)
                        print(f"Parsed social_platforms: {social_platforms}")
                        
                        # Ensure it's a list
                        if not isinstance(social_platforms, list):
                            social_platforms = [social_platforms]
                        
                        # Update the request data
                        request.data._mutable = True
                        request.data['social_platforms'] = social_platforms
                        request.data._mutable = False
                    except json.JSONDecodeError as e:
                        print(f"Error parsing social_platforms JSON: {e}")
                        print(f"ADD INFLUENCER - Raw social_platforms string: {social_platforms}")
                        # Set to empty list if parsing fails
                        request.data._mutable = True
                        request.data['social_platforms'] = []
                        request.data._mutable = False
                elif isinstance(social_platforms, list):
                    # It's already a list, no need to parse
                    pass
                else:
                    # Convert to list if it's not a list
                    request.data._mutable = True
                    request.data['social_platforms'] = []
                    request.data._mutable = False
            else:
                # Set to empty list if not present
                request.data._mutable = True
                request.data['social_platforms'] = []
                request.data._mutable = False

            update_data = {
                'name': request.data.get('name'),
                'platform': request.data.get('platform'),
                'followers_count': request.data.get('followers_count'),
                'niche': request.data.get('niche'),
                'social_media_handle': request.data.get('social_media_handle'),
                'region': request.data.get('region'),
                'demography': request.data.get('demography'),
                'base_fee': request.data.get('base_fee'),
                'interests': request.data.get('interests', ''),
                'bio': request.data.get('bio', ''),
                'social_platforms': social_platforms,
                'instagram_url': request.data.get('instagram_url', ''),
                'tiktok_url': request.data.get('tiktok_url', ''),
                'youtube_url': request.data.get('youtube_url', ''),
                'twitter_url': request.data.get('twitter_url', '')
            }
            
            serializer = self.get_serializer(instance, data=update_data, partial=True)
            
            if serializer.is_valid():
                updated_instance = serializer.save()
                print("Update successful:", serializer.data)  # Debug print
                
                # Return the updated data
                return Response({
                    'message': 'Influencer updated successfully',
                    'data': serializer.data
                }, status=status.HTTP_200_OK)
            else:
                print("Validation errors:", serializer.errors)  # Debug print
                return Response({
                    'error': 'Invalid data',
                    'details': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Influencer.DoesNotExist:
            return Response({
                'error': 'Influencer not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(f"Error updating influencer: {str(e)}")  # Debug print
            return Response({
                'error': 'Failed to update influencer',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
def register_view(request):
    try:
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')
        role = request.data.get('role')
        
        if not all([username, email, password, role]):
            return Response({
                'error': 'Please provide all required fields'
            }, status=400)
            
        # Check if role is valid
        if role not in ['client', 'influencer']:
            return Response({
                'error': 'Invalid role. Must be either "client" or "influencer"'
            }, status=400)
            
        # Check if username already exists
        if User.objects.filter(username=username).exists():
            return Response({
                'error': 'Username already exists'
            }, status=400)
            
        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )
        
        # Create profile with specified role
        Profile.objects.create(user=user, role=role)
        
        # If role is influencer, create an Influencer profile
        if role == 'influencer':
            try:
                Influencer.objects.create(
                    user=user,  # Try with user field
                    name=username,
                    platform="Instagram",
                    niche="General",
                    followers_count=0
                )
            except Exception as e:
                # If that fails, try without user field
                print(f"Error creating influencer with user: {str(e)}")
                try:
                    Influencer.objects.create(
                        name=username,
                        platform="Instagram",
                        niche="General",
                        followers_count=0
                    )
                except Exception as e2:
                    print(f"Error creating influencer without user: {str(e2)}")
                    # Continue anyway, we at least have the user and profile
        
        # Generate token
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'message': 'Registration successful',
            'token': str(refresh.access_token),
            'role': role,
            'username': user.username
        })
        
    except Exception as e:
        return Response({
            'error': f'Registration failed: {str(e)}'
        }, status=500)

@api_view(['GET'])
def match_influencers(request, campaign_id):
    try:
        campaign = Campaign.objects.get(id=campaign_id)
        influencers = Influencer.objects.all()
        matched_influencers = []

        # Debug prints
        print(f"Campaign details: {campaign.__dict__}")
        print(f"Total influencers: {influencers.count()}")

        for influencer in influencers:
            try:
                match_score = 0
                match_details = []

                # Safely handle platforms comparison
                campaign_platforms = campaign.platforms if isinstance(campaign.platforms, list) else []
                if influencer.platform and campaign_platforms and influencer.platform in campaign_platforms:
                    match_score += 2
                    match_details.append("Platform match")

                # Safely handle region comparison
                try:
                    campaign_region = str(campaign.region).lower() if campaign.region else ""
                    influencer_region = str(influencer.demography).lower() if influencer.demography else ""
                    
                    if campaign_region and influencer_region and (
                        campaign_region in influencer_region or 
                        influencer_region in campaign_region
                    ):
                        match_score += 2
                        match_details.append("Region match")
                except Exception as e:
                    print(f"Error in region matching: {str(e)}")

                # Safely handle demographics comparison
                if campaign.demography and influencer.demography and (
                    str(campaign.demography).lower() == str(influencer.demography).lower()
                ):
                    match_score += 1.5
                    match_details.append("Demographics match")

                # Safely handle industry/niche comparison
                campaign_industry = str(campaign.industry).lower() if campaign.industry else ""
                influencer_niche = str(influencer.niche).lower() if influencer.niche else ""
                
                if campaign_industry and influencer_niche and (
                    campaign_industry in influencer_niche or 
                    influencer_niche in campaign_industry
                ):
                    match_score += 1.5
                    match_details.append("Industry/Niche match")

                # Safely handle follower count comparison
                try:
                    budget = float(campaign.budget) if campaign.budget else 0
                    followers = int(influencer.followers_count) if influencer.followers_count else 0
                    budget_based_follower_min = budget * 10

                    if followers >= budget_based_follower_min:
                        match_score += 1
                        match_details.append("Follower count match")
                except Exception as e:
                    print(f"Error in follower count matching: {str(e)}")

                # Include any influencer with a match
                if match_score > 0:
                    matched_influencers.append({
                        'id': influencer.id,
                        'name': influencer.name,
                        'platform': influencer.platform,
                        'followers_count': influencer.followers_count,
                        'profile_picture': influencer.get_profile_picture(),
                        'social_media_handle': influencer.social_media_handle,
                        'match_score': round(match_score, 2),
                        'match_percentage': round((match_score / 8) * 100, 1),
                        'match_details': match_details,
                        'niche': influencer.niche,
                        'region': influencer.demography,
                        'instagram_url': influencer.instagram_url,
                        'tiktok_url': influencer.tiktok_url,
                        'youtube_url': influencer.youtube_url,
                        'twitter_url': influencer.twitter_url,
                        'interests': influencer.interests,
                        'demography': influencer.demography,
                    })

            except Exception as e:
                print(f"Error processing influencer {influencer.id}: {str(e)}")
                continue

        # Sort by match score
        matched_influencers.sort(key=lambda x: x['match_score'], reverse=True)

        # Add rankings
        for i, influencer in enumerate(matched_influencers):
            influencer['rank'] = i + 1

        print(f"Found {len(matched_influencers)} matches")

        return Response({
            'campaign': {
                'name': campaign.name,
                'industry': campaign.industry,
                'platforms': campaign.platforms,
                'region': campaign.region,
                'demography': campaign.demography,
                'budget': float(campaign.budget) if campaign.budget else 0
            },
            'matches': matched_influencers,
            'total_matches': len(matched_influencers)
        })

    except Campaign.DoesNotExist:
        print(f"Campaign {campaign_id} not found")
        return Response(
            {'error': 'Campaign not found'}, 
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        print(f"Error in match_influencers: {str(e)}")
        return Response(
            {'error': str(e)}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
def booking_detail(request, booking_id):
    try:
        booking = Booking.objects.get(id=booking_id)
        serializer = BookingSerializer(booking)
        return Response(serializer.data)
    except Booking.DoesNotExist:
        return Response(
            {'error': 'Booking not found'}, 
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {'error': str(e)}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

# Add these admin-specific views
@api_view(['GET'])
def admin_list_users(request):
    users = User.objects.all()
    data = [{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.profile.role if hasattr(user, 'profile') else 'N/A',
        'date_joined': user.date_joined
    } for user in users]
    return Response(data)

@api_view(['GET'])
def admin_list_campaigns(request):
    campaigns = Campaign.objects.all()
    serializer = CampaignSerializer(campaigns, many=True)
    return Response(serializer.data)

@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
def admin_add_influencer(request):
    """
    Add a new influencer (admin only)
    """
    try:
        # Create a mutable copy of the request data
        mutable_data = request.data.copy()
        
        # Set social_platforms to an empty list by default
        mutable_data['social_platforms'] = []
        
        # Debug the request data
        print("ADD INFLUENCER - Request data:", {
            key: request.data.get(key) for key in request.data.keys()
        })
        
        # Create the serializer with the processed data
        serializer = InfluencerSerializer(data=mutable_data)
        
        if serializer.is_valid():
            influencer = serializer.save()
            print(f"ADD INFLUENCER - Saved influencer with social_platforms: {influencer.social_platforms}")
            return Response({
                'message': 'Influencer added successfully',
                'influencer': {
                    'id': influencer.id,
                    'name': influencer.name
                }
            })
        else:
            print("ADD INFLUENCER - Validation errors:", serializer.errors)
            return Response({
                'error': 'Invalid data',
                'details': serializer.errors
            }, status=400)
    except Exception as e:
        print(f"ADD INFLUENCER - Error: {str(e)}")
        traceback.print_exc()  # Print the full traceback
        return Response({
            'error': str(e)
        }, status=500)

@api_view(['GET'])
def admin_list_bookings(request):
    try:
        bookings = Booking.objects.all().order_by('-created_at')
        data = []
        for booking in bookings:
            data.append({
                'id': booking.id,
                'influencer': {
                    'id': booking.influencer.id,
                    'name': booking.influencer.name,
                    'platform': booking.influencer.platform,
                    'followers_count': booking.influencer.followers_count,
                },
                'campaign': {
                    'id': booking.campaign.id,
                    'name': booking.campaign.name,
                    'objective': booking.campaign.objective,
                    'budget': str(booking.campaign.budget),
                },
                'user': {
                    'id': booking.campaign.owner.id,
                    'username': booking.campaign.owner.username,
                    'email': booking.campaign.owner.email,
                } if booking.campaign.owner else None,
                'status': booking.status,
                'created_at': booking.created_at
            })
        return Response(data)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['GET'])
def admin_list_influencers(request):
    try:
        # Check if social_platforms field exists
        from django.db import connection
        cursor = connection.cursor()
        cursor.execute("PRAGMA table_info(influencers_influencer)")
        columns = [column[1] for column in cursor.fetchall()]
        
        has_social_platforms = 'social_platforms' in columns
        has_bio = 'bio' in columns
        
        # Get all influencers
        influencers = Influencer.objects.all()
        
        # Manually serialize to avoid the missing field
        data = []
        for influencer in influencers:
            item = {
                'id': influencer.id,
                'name': influencer.name,
                'platform': influencer.platform,
                'niche': influencer.niche,
                'followers_count': influencer.followers_count,
                'region': influencer.region,
                'demography': influencer.demography,
                'base_fee': influencer.base_fee,
                'instagram_url': influencer.instagram_url,
                'tiktok_url': influencer.tiktok_url,
                'youtube_url': influencer.youtube_url,
                'twitter_url': influencer.twitter_url,
            }
            
            # Only include social_platforms if the field exists
            if has_social_platforms:
                item['social_platforms'] = influencer.social_platforms
            else:
                item['social_platforms'] = []
                
            # Only include bio if the field exists
            if has_bio:
                item['bio'] = influencer.bio
            else:
                item['bio'] = ''
                
            data.append(item)
            
        # Debug the data being sent
        print("Sending influencer data:", data)
        
        return Response(data)
    except Exception as e:
        print(f"Error in admin_list_influencers: {str(e)}")
        return Response({'error': str(e)}, status=500)

@api_view(['GET'])
def admin_list_campaigns(request):
    try:
        campaigns = Campaign.objects.all()
        serializer = CampaignSerializer(campaigns, many=True)
        return Response(serializer.data)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['DELETE'])
def admin_delete_campaign(request, pk):
    try:
        campaign = Campaign.objects.get(pk=pk)
        campaign.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    except Campaign.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

@api_view(['PUT'])
def admin_edit_influencer(request, pk):
    try:
        influencer = Influencer.objects.get(pk=pk)
        print(f"Current social_platforms: {influencer.social_platforms}")
        print(f"Current URLs: Instagram={influencer.instagram_url}, TikTok={influencer.tiktok_url}, YouTube={influencer.youtube_url}, Twitter={influencer.twitter_url}")
    except Influencer.DoesNotExist:
        return Response({'error': 'Influencer not found'}, status=404)

    try:
        print("Received data:", request.data)
        
        # Debug the social_platforms data specifically
        social_platforms = request.data.get('social_platforms')
        print(f"Received social_platforms: {social_platforms}, type: {type(social_platforms)}")
        
        # Debug the URLs
        instagram_url = request.data.get('instagram_url')
        tiktok_url = request.data.get('tiktok_url')
        youtube_url = request.data.get('youtube_url')
        twitter_url = request.data.get('twitter_url')
        print(f"Received URLs: Instagram={instagram_url}, TikTok={tiktok_url}, YouTube={youtube_url}, Twitter={twitter_url}")
        
        # Ensure it's a list
        if not isinstance(social_platforms, list):
            print(f"Converting social_platforms to list: {social_platforms}")
            social_platforms = [social_platforms] if social_platforms else []
        
        print(f"Final social_platforms before update: {social_platforms}")
        
        update_data = {
            'name': request.data.get('name'),
            'platform': request.data.get('platform'),
            'followers_count': request.data.get('followers_count'),
            'niche': request.data.get('niche'),
            'social_media_handle': request.data.get('social_media_handle'),
            'region': request.data.get('region'),
            'demography': request.data.get('demography'),
            'base_fee': request.data.get('base_fee'),
            'interests': request.data.get('interests', ''),
            'bio': request.data.get('bio', ''),
            'social_platforms': social_platforms,
            'instagram_url': instagram_url,
            'tiktok_url': tiktok_url,
            'youtube_url': youtube_url,
            'twitter_url': twitter_url
        }
        
        serializer = InfluencerSerializer(influencer, data=update_data, partial=True)
        if serializer.is_valid():
            updated_influencer = serializer.save()
            print(f"Saved social_platforms: {updated_influencer.social_platforms}")
            print(f"Saved URLs: Instagram={updated_influencer.instagram_url}, TikTok={updated_influencer.tiktok_url}, YouTube={updated_influencer.youtube_url}, Twitter={updated_influencer.twitter_url}")
            return Response(serializer.data)
        
        print("Validation errors:", serializer.errors)
        return Response(serializer.errors, status=400)
        
    except Exception as e:
        print(f"Error updating influencer: {str(e)}")
        return Response({'error': str(e)}, status=400)

@api_view(['DELETE'])
def admin_delete_influencer(request, pk):
    try:
        influencer = Influencer.objects.get(pk=pk)
        influencer.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    except Influencer.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
def admin_update_booking_status(request, pk):
    try:
        booking = Booking.objects.get(pk=pk)
        new_status = request.data.get('status')
        
        if new_status not in ['approved', 'rejected', 'pending', 'completed']:
            return Response(
                {'error': 'Invalid status'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        booking.status = new_status
        booking.save()

        # If booking is approved, create a notification
        if new_status == 'approved' and booking.campaign.owner:
            InfluencerNotification.objects.create(
                influencer=booking.influencer,
                message=f"Your booking for campaign '{booking.campaign.name}' has been approved. Please proceed with payment."
            )
            print(f"Created notification for booking {pk}")

        return Response({
            'message': f'Booking status updated to {new_status}',
            'booking_id': booking.id,
            'status': new_status
        })

    except Booking.DoesNotExist:
        return Response(
            {'error': 'Booking not found'}, 
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        print(f"Error updating booking status: {str(e)}")
        return Response(
            {'error': str(e)}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
def admin_booking_detail(request, booking_id):
    try:
        booking = Booking.objects.get(id=booking_id)
        data = {
            'id': booking.id,
            'status': booking.status,
            'created_at': booking.created_at,
            'updated_at': booking.updated_at,
            'amount': booking.amount,
            'user': {
                'id': booking.user.id,
                'username': booking.user.username,
                'email': booking.user.email,
                'date_joined': booking.user.date_joined
            } if booking.user else None,
            'campaign': {
                'id': booking.campaign.id,
                'name': booking.campaign.name,
                'platforms': booking.campaign.platforms,
                'budget': booking.campaign.budget,
                'objective': booking.campaign.objective,
                'industry': booking.campaign.industry,
                'region': booking.campaign.region
            } if booking.campaign else None,
            'influencer': {
                'id': booking.influencer.id,
                'name': booking.influencer.name,
                'platform': booking.influencer.platform,
                'followers_count': booking.influencer.followers_count,
                'niche': booking.influencer.niche,
                'region': booking.influencer.region
            } if booking.influencer else None
        }
        return Response(data)
    except Booking.DoesNotExist:
        return Response(
            {'error': 'Booking not found'}, 
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {'error': str(e)}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
def admin_get_campaign_details(request, pk):
    try:
        campaign = Campaign.objects.prefetch_related(
            'bookings',
            'bookings__influencer',
            'bookings__payment_set'
        ).get(pk=pk)
        
        try:
            # Serialize campaign data with detailed information
            data = {
                'id': campaign.id,
                'name': campaign.name,
                'objective': campaign.objective,
                'platforms': campaign.platforms or [],  # Handle null platforms
                'budget': str(campaign.budget) if campaign.budget else "0.00",
                'demography': campaign.demography or "",
                'gender': campaign.gender or "",
                'region': campaign.region or "",
                'industry': campaign.industry or "",
                'owner': None,  # Initialize as None
                'bookings': [],  # Initialize as empty list
                'created_at': campaign.created_at
            }

            # Add owner data if exists
            if campaign.owner:
                data['owner'] = {
                    'id': campaign.owner.id,
                    'username': campaign.owner.username,
                    'email': campaign.owner.email
                }

            # Add bookings data
            for booking in campaign.bookings.all():
                try:
                    booking_data = {
                        'id': booking.id,
                        'status': booking.status,
                        'created_at': booking.created_at,
                        'influencer': {
                            'id': booking.influencer.id,
                            'name': booking.influencer.name,
                            'platform': booking.influencer.platform,
                            'followers_count': booking.influencer.followers_count,
                            'base_fee': str(booking.influencer.base_fee)
                        },
                        'payment_status': None
                    }
                    
                    # Add payment status if exists
                    payment = booking.payment_set.first()
                    if payment:
                        booking_data['payment_status'] = payment.status
                        
                    data['bookings'].append(booking_data)
                except Exception as e:
                    print(f"Error processing booking {booking.id}: {str(e)}")
                    continue
            
            return Response(data)
            
        except Exception as e:
            print(f"Error serializing campaign data: {str(e)}")
            return Response(
                {'error': f'Error processing campaign data: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
    except Campaign.DoesNotExist:
        return Response(
            {'error': 'Campaign not found'}, 
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        print(f"Error fetching campaign details: {str(e)}")
        return Response(
            {'error': str(e)}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
def initiate_payment(request, booking_id):
    try:
        booking = Booking.objects.get(id=booking_id)
        
        # Check if booking is approved
        if booking.status != 'approved':
            return Response({
                'error': 'Payment can only be initiated for approved bookings'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if payment already exists
        if Payment.objects.filter(booking=booking, status='completed').exists():
            return Response({
                'error': 'Payment already completed for this booking'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Create payment record
        payment = Payment.objects.create(
            booking=booking,
            amount=booking.campaign.budget,
            status='pending'
        )

        return Response({
            'payment_id': payment.id,
            'amount': payment.amount,
            'booking_id': booking.id,
            'campaign_name': booking.campaign.name
        })

    except Booking.DoesNotExist:
        return Response({'error': 'Booking not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['POST'])
def complete_payment(request, payment_id):
    try:
        payment = Payment.objects.get(id=payment_id)
        
        # Add your payment processing logic here
        # This is where you'd integrate with a payment gateway
        
        payment.status = 'completed'
        payment.transaction_id = 'mock_transaction_id'  # Replace with actual transaction ID
        payment.save()

        # Update booking status
        payment.booking.status = 'paid'
        payment.booking.save()

        return Response({
            'message': 'Payment completed successfully',
            'transaction_id': payment.transaction_id
        })

    except Payment.DoesNotExist:
        return Response({'error': 'Payment not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_approved_bookings(request):
    try:
        # Get approved bookings for the current user's campaigns
        bookings = Booking.objects.filter(
            status='approved',
            campaign__owner=request.user
        )
        
        # Filter out bookings with completed payments if the Payment table exists
        try:
            bookings = bookings.exclude(payment__status='completed')
        except Exception as e:
            print(f"Payment table might not exist yet: {str(e)}")
        
        print(f"Found {bookings.count()} approved bookings for user {request.user}")
        
        data = []
        for booking in bookings:
            data.append({
                'id': booking.id,
                'campaign': {
                    'id': booking.campaign.id,
                    'name': booking.campaign.name,
                    'budget': str(booking.campaign.budget)
                },
                'influencer': {
                    'id': booking.influencer.id,
                    'name': booking.influencer.name,
                    'platform': booking.influencer.platform
                },
                'status': booking.status,
                'created_at': booking.created_at
            })
        return Response(data)
    except Exception as e:
        print(f"Error in get_approved_bookings: {str(e)}")
        return Response({'error': str(e)}, status=500)

@api_view(['GET'])
def list_campaigns(request):
    try:
        campaigns = Campaign.objects.prefetch_related('bookings').filter(owner=request.user)
        serializer = CampaignSerializer(campaigns, many=True)
        return Response(serializer.data)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def influencer_dashboard(request):
    """
    Get dashboard data for influencers
    """
    try:
        # Get the influencer profile
        print(f"Looking for influencer profile for user: {request.user.username}")
        influencer = Influencer.objects.get(user=request.user)
        print(f"Found influencer: {influencer.name}")
        
        # Get bookings for this influencer
        bookings = Booking.objects.filter(influencer=influencer)
        
        # Calculate statistics
        stats = {
            'totalCampaigns': bookings.count(),
            'activeBookings': bookings.filter(status='approved').count(),
            'earnings': sum(booking.campaign.budget for booking in bookings.filter(status='completed')),
            'pendingRequests': bookings.filter(status='pending').count()
        }
        
        # Get recent campaign requests
        recent_campaigns = [{
            'id': booking.campaign.id,
            'name': booking.campaign.name,
            'brand': booking.campaign.owner.username if booking.campaign.owner else 'Unknown',
            'status': booking.status,
            'budget': float(booking.campaign.budget),
            'created_at': booking.created_at
        } for booking in bookings.order_by('-created_at')[:5]]

        return Response({
            'stats': stats,
            'campaigns': recent_campaigns
        })

    except Influencer.DoesNotExist:
        return Response({
            'error': 'Influencer profile not found'
        }, status=404)
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=500)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def influencer_bookings(request):
    """
    Get all bookings for the logged-in influencer
    """
    try:
        influencer = Influencer.objects.get(user=request.user)
        
        # Get all bookings for this influencer
        bookings = Booking.objects.filter(influencer=influencer)
        
        # Prepare the response data
        bookings_data = []
        
        for booking in bookings:
            campaign = booking.campaign
            
            booking_data = {
                'id': booking.id,
                'campaign': {
                    'id': campaign.id,
                    'name': campaign.name,
                    'description': campaign.objective,
                    'budget': float(campaign.budget),
                    'platforms': campaign.platforms
                },
                'status': booking.status,
                'created_at': booking.created_at,
                'name': campaign.name,  # For compatibility with existing code
                'description': campaign.objective,
                'brand_name': campaign.owner.username if campaign.owner else 'Unknown',
                'platform': campaign.platforms[0] if campaign.platforms else 'Multiple',
                'budget': float(campaign.budget)
            }
            
            bookings_data.append(booking_data)
        
        return Response(bookings_data)
        
    except Influencer.DoesNotExist:
        return Response({
            'error': 'Influencer profile not found'
        }, status=404)
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=500)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def influencer_dashboard_stats(request):
    """
    Get dashboard statistics for the logged-in influencer
    """
    try:
        influencer = Influencer.objects.get(user=request.user)
        bookings = Booking.objects.filter(influencer=influencer)
        
        stats = {
            'totalCampaigns': bookings.count(),
            'activeBookings': bookings.filter(status='approved').count(),
            'earnings': sum(booking.campaign.budget for booking in bookings.filter(status='completed')),
            'pendingRequests': bookings.filter(status='pending').count()
        }
        
        return Response(stats)
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=500)

@api_view(['GET'])
def debug_influencers(request):
    """
    Debug endpoint to check influencer data
    """
    try:
        influencers = Influencer.objects.all()
        data = []
        
        for influencer in influencers:
            item = {
                'id': influencer.id,
                'name': influencer.name,
                'platform': influencer.platform,
                'niche': influencer.niche,
                'followers_count': influencer.followers_count,
                'has_user': influencer.user is not None,
                'user_id': influencer.user.id if influencer.user else None,
                'user_username': influencer.user.username if influencer.user else None
            }
            data.append(item)
        
        return Response({
            'count': len(data),
            'influencers': data
        })
    except Exception as e:
        return Response({
            'error': str(e),
            'traceback': traceback.format_exc()
        }, status=500)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def influencer_profile_setup(request):
    """
    Setup or update influencer profile after registration
    """
    try:
        # Check if user already has an influencer profile
        try:
            influencer = Influencer.objects.get(user=request.user)
            # Update existing profile
            serializer = InfluencerSerializer(influencer, data=request.data, partial=True)
        except Influencer.DoesNotExist:
            # Create new profile
            data = request.data.copy()
            data['user'] = request.user.id
            serializer = InfluencerSerializer(data=data)
        
        if serializer.is_valid():
            influencer = serializer.save()
            
            # Update user profile to ensure role is set to influencer
            profile, created = Profile.objects.get_or_create(
                user=request.user,
                defaults={'role': 'influencer'}
            )
            if not created and profile.role != 'influencer':
                profile.role = 'influencer'
                profile.save()
            
            return Response({
                'message': 'Profile updated successfully',
                'profile': serializer.data
            })
        else:
            return Response({
                'error': 'Invalid data',
                'details': serializer.errors
            }, status=400)
            
    except Exception as e:
        print(f"Error in influencer_profile_setup: {str(e)}")
        return Response({
            'error': str(e)
        }, status=500)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def influencer_profile_status(request):
    """
    Check if the influencer profile is complete
    """
    try:
        print(f"Checking profile status for user: {request.user.username}")
        
        # TESTING: Force incomplete profile
        return Response({
            'isComplete': False,
            'missingFields': ['test']
        })
        
        # Rest of the function...
    except Exception as e:
        print(f"Error in influencer_profile_status: {str(e)}")
        return Response({
            'error': str(e)
        }, status=500)

@api_view(['GET'])
def test_api(request):
    """
    Simple test endpoint to verify API is working
    """
    return Response({
        'message': 'API is working',
        'authenticated': request.user.is_authenticated,
        'user': request.user.username if request.user.is_authenticated else None
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def influencer_my_profile(request):
    """
    Get the logged-in influencer's profile
    """
    try:
        print(f"Fetching profile for user: {request.user.username}")
        
        try:
            influencer = Influencer.objects.get(user=request.user)
            print(f"Found influencer profile: {influencer.name}")
            
            # Use a simpler approach to avoid serialization issues
            data = {
                'id': influencer.id,
                'name': influencer.name,
                'gender': influencer.gender if hasattr(influencer, 'gender') else '',
                'platform': influencer.platform,
                'niche': influencer.niche,
                'followers_count': influencer.followers_count,
                'social_media_handle': influencer.social_media_handle if hasattr(influencer, 'social_media_handle') else '',
                'region': influencer.region if hasattr(influencer, 'region') else '',
                'interests': influencer.interests if hasattr(influencer, 'interests') else '',
                'bio': influencer.bio if hasattr(influencer, 'bio') else '',
                'instagram_url': influencer.instagram_url if hasattr(influencer, 'instagram_url') else '',
                'tiktok_url': influencer.tiktok_url if hasattr(influencer, 'tiktok_url') else '',
                'youtube_url': influencer.youtube_url if hasattr(influencer, 'youtube_url') else '',
                'twitter_url': influencer.twitter_url if hasattr(influencer, 'twitter_url') else '',
            }
            
            # Add profile picture URL if it exists
            if hasattr(influencer, 'profile_picture') and influencer.profile_picture:
                data['profile_picture'] = request.build_absolute_uri(influencer.profile_picture.url)
            
            return Response(data)
            
        except Influencer.DoesNotExist:
            print(f"No influencer profile found for user: {request.user.username}")
            
            # Create a basic profile for the user
            influencer = Influencer.objects.create(
                user=request.user,
                name=request.user.username,
                platform="Instagram",
                niche="General",
                followers_count=0
            )
            
            return Response({
                'id': influencer.id,
                'name': influencer.name,
                'platform': influencer.platform,
                'niche': influencer.niche,
                'followers_count': influencer.followers_count,
                'message': 'Created new profile'
            })
            
    except Exception as e:
        print(f"Error in influencer_my_profile: {str(e)}")
        import traceback
        traceback.print_exc()
        return Response({
            'error': str(e),
            'traceback': traceback.format_exc()
        }, status=500)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def influencer_profile_update(request):
    """
    Update the logged-in influencer's profile
    """
    try:
        influencer = Influencer.objects.get(user=request.user)
        serializer = InfluencerSerializer(influencer, data=request.data, partial=True)
        
        if serializer.is_valid():
            serializer.save()
            return Response({
                'message': 'Profile updated successfully',
                'profile': serializer.data
            })
        else:
            return Response({
                'error': 'Invalid data',
                'details': serializer.errors
            }, status=400)
    except Influencer.DoesNotExist:
        return Response({
            'error': 'Influencer profile not found'
        }, status=404)
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=500)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def test_auth(request):
    """
    Test endpoint to verify authentication
    """
    return Response({
        'message': 'Authentication successful',
        'user': request.user.username,
        'user_id': request.user.id
    })

@api_view(['PUT'])
def update_influencer_profile(request):
    try:
        # Get the influencer associated with the current user
        influencer = Influencer.objects.get(user=request.user)
        
        # Update the influencer fields
        if 'name' in request.data:
            influencer.name = request.data['name']
        
        if 'email' in request.data:
            # Update the user's email
            request.user.email = request.data['email']
            request.user.save()
        
        if 'phone' in request.data:
            # Store phone in the profile
            profile = request.user.profile
            profile.phone = request.data['phone']
            profile.save()
        
        if 'gender' in request.data:
            # Store gender in the profile
            profile = request.user.profile
            profile.gender = request.data['gender']
            profile.save()
        
        # ... other fields ...
        
        # Save the influencer
        influencer.save()
        
        # Return the updated data
        return Response({
            'message': 'Profile updated successfully',
            'name': influencer.name,
            'email': request.user.email,
            'phone': request.user.profile.phone if hasattr(request.user, 'profile') else '',
            'gender': request.user.profile.gender if hasattr(request.user, 'profile') else '',
            # ... other fields ...
        })
    except Influencer.DoesNotExist:
        return Response({'error': 'Influencer profile not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def influencer_campaigns(request):
    """
    Get all campaigns for the logged-in influencer
    """
    try:
        influencer = Influencer.objects.get(user=request.user)
        
        # Get all bookings for this influencer
        bookings = Booking.objects.filter(influencer=influencer)
        
        # Prepare the response data
        campaigns_data = []
        
        for booking in bookings:
            campaign = booking.campaign
            
            # Get campaign submissions if any
            submissions = []
            # You would need to create a model for submissions
            # This is just a placeholder
            
            campaign_data = {
                'id': campaign.id,
                'name': campaign.name,
                'description': campaign.objective,
                'brand_name': campaign.owner.username if campaign.owner else 'Unknown',
                'platform': campaign.platforms[0] if campaign.platforms else 'Multiple',
                'budget': float(campaign.budget),
                'created_at': campaign.created_at,
                'booking_date': booking.created_at,
                'acceptance_date': booking.updated_at if booking.status in ['approved', 'completed'] else None,
                'status': booking.status,
                'content_submissions': submissions,
                'end_date': campaign.created_at + timedelta(days=30),  # Example: 30 days from creation
                'completion_date': booking.updated_at if booking.status == 'completed' else None,
                'payment_date': None,  # You would need to add this from your payment model
                'content_deadline': campaign.created_at + timedelta(days=15),  # Example: 15 days from creation
                'content_submitted': False  # You would need to check this from your submissions model
            }
            
            campaigns_data.append(campaign_data)
        
        return Response(campaigns_data)
        
    except Influencer.DoesNotExist:
        return Response({
            'error': 'Influencer profile not found'
        }, status=404)
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=500)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def accept_campaign(request, campaign_id):
    """
    Accept a campaign booking
    """
    try:
        influencer = Influencer.objects.get(user=request.user)
        booking = Booking.objects.get(campaign_id=campaign_id, influencer=influencer)
        
        if booking.status != 'pending':
            return Response({
                'error': 'This booking is not in pending status'
            }, status=400)
        
        booking.status = 'approved'
        booking.save()
        
        return Response({
            'message': 'Campaign accepted successfully'
        })
        
    except (Influencer.DoesNotExist, Booking.DoesNotExist):
        return Response({
            'error': 'Booking not found'
        }, status=404)
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=500)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def decline_campaign(request, campaign_id):
    """
    Decline a campaign booking
    """
    try:
        influencer = Influencer.objects.get(user=request.user)
        booking = Booking.objects.get(campaign_id=campaign_id, influencer=influencer)
        
        if booking.status != 'pending':
            return Response({
                'error': 'This booking is not in pending status'
            }, status=400)
        
        booking.status = 'rejected'
        booking.save()
        
        return Response({
            'message': 'Campaign declined successfully'
        })
        
    except (Influencer.DoesNotExist, Booking.DoesNotExist):
        return Response({
            'error': 'Booking not found'
        }, status=404)
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=500)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def campaign_assets(request, campaign_id):
    """
    Get assets for a specific campaign
    """
    try:
        influencer = Influencer.objects.get(user=request.user)
        booking = Booking.objects.get(campaign_id=campaign_id, influencer=influencer)
        
        # This is a placeholder - you would need to create a model for campaign assets
        # For now, we'll return some dummy data
        assets = [
            {
                'id': 1,
                'name': 'Brand Guidelines',
                'description': 'Official brand guidelines and messaging requirements',
                'file_type': 'pdf',
                'size': '2.4 MB',
                'uploaded_at': booking.created_at,
                'url': 'https://example.com/assets/brand_guidelines.pdf',
                'type': 'file'
            },
            {
                'id': 2,
                'name': 'Product Images',
                'description': 'High-resolution product images for your content',
                'file_type': 'image',
                'size': '5.1 MB',
                'uploaded_at': booking.created_at,
                'url': 'https://example.com/assets/product_images.zip',
                'type': 'file'
            },
            {
                'id': 3,
                'name': 'Campaign Brief',
                'description': 'Detailed information about campaign goals and requirements',
                'file_type': 'docx',
                'size': '1.2 MB',
                'uploaded_at': booking.created_at,
                'url': 'https://example.com/assets/campaign_brief.docx',
                'type': 'file'
            },
            {
                'id': 4,
                'name': 'Product Website',
                'description': 'Official product website for reference',
                'file_type': 'link',
                'size': 'N/A',
                'uploaded_at': booking.created_at,
                'url': 'https://example.com/product',
                'type': 'link'
            }
        ]
        
        return Response(assets)
        
    except (Influencer.DoesNotExist, Booking.DoesNotExist):
        return Response({
            'error': 'Booking not found'
        }, status=404)
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=500)

@api_view(['POST'])
def quick_add_influencer(request):
    try:
        data = request.data
        
        # Create influencer object
        influencer = Influencer.objects.create(
            name=data['name'],
            platform=data['platform'],
            followers_count=int(data['followers_count']),
            niche=data['niche'],
            social_media_handle=data['social_media_handle'],
            region=data['region'],
            bio=data.get('bio', ''),
            social_platforms=data.get('social_platforms', []),
            demography=data.get('demography', ''),
            instagram_url=next((p['url'] for p in data.get('social_platforms', []) if p['platform'] == 'Instagram'), None),
            tiktok_url=next((p['url'] for p in data.get('social_platforms', []) if p['platform'] == 'TikTok'), None),
            youtube_url=next((p['url'] for p in data.get('social_platforms', []) if p['platform'] == 'YouTube'), None),
            twitter_url=next((p['url'] for p in data.get('social_platforms', []) if p['platform'] == 'Twitter'), None)
        )
        
        return Response({
            'message': 'Influencer added successfully',
            'id': influencer.id
        }, status=201)
        
    except KeyError as e:
        return Response({
            'error': f'Missing required field: {str(e)}'
        }, status=400)
    except Exception as e:
        print(f"Error creating influencer: {str(e)}")  # For debugging
        return Response({
            'error': str(e)
        }, status=400)

@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
def upload_influencers_excel(request):
    try:
        excel_file = request.FILES.get('file')
        if not excel_file:
            return Response({'error': 'No file uploaded'}, status=400)
        
        # Check file extension
        if not excel_file.name.endswith(('.xlsx', '.xls')):
            return Response({'error': 'File must be an Excel file (.xlsx or .xls)'}, status=400)
        
        # Read Excel file
        df = pd.read_excel(excel_file)
        
        # Validate required columns
        required_columns = ['name']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            return Response({
                'error': f'Missing required columns: {", ".join(missing_columns)}'
            }, status=400)
        
        # Process data
        success_count = 0
        error_count = 0
        errors = []
        
        for index, row in df.iterrows():
            try:
                # Skip rows that contain "DATA RECEIVED" as these are metadata rows
                if isinstance(row['name'], str) and "DATA RECEIVED" in row['name']:
                    continue
                
                # Check if essential fields are present
                if pd.isna(row['name']):
                    error_count += 1
                    errors.append(f"Row {index+2}: Missing name")
                    continue
                
                # Get the platform column value
                platform_text = str(row.get('platform', '')) if not pd.isna(row.get('platform', '')) else ''
                platform_text = platform_text.replace('"', '').strip()  # Remove quotes and extra spaces
                
                # Split the platform text by newlines to get multiple platforms
                platform_entries = [p.strip() for p in platform_text.split('\n') if p.strip()]
                
                # Parse each platform entry
                social_platforms = []
                primary_platform = None
                primary_followers = 0
                
                for platform_entry in platform_entries:
                    # Default values
                    platform_name = "Unknown"
                    social_media_handle = ""
                    followers_count = 0
                    profile_url = ""
                    
                    # Extract platform name
                    if ":" in platform_entry:
                        platform_name = platform_entry.split(':')[0].strip()
                    
                    # Extract handle - look for @username pattern
                    handle_match = re.search(r'@(\w+)', platform_entry)
                    if handle_match:
                        social_media_handle = handle_match.group(0)
                    
                    # Extract followers count - look for numbers followed by "followers"
                    followers_match = re.search(r'(\d+)\s*followers', platform_entry)
                    if followers_match:
                        followers_count = int(followers_match.group(1))
                    
                    # Extract URL - look for http or domain patterns
                    url_match = re.search(r'(https?://[^\s\n]+|(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+(?:/\S*)?)', platform_entry)
                    if url_match:
                        profile_url = url_match.group(0).strip()
                        # Add https:// if missing
                        if profile_url and not profile_url.startswith(('http://', 'https://')):
                            profile_url = 'https://' + profile_url
                    
                    # Add to social platforms list
                    platform_data = {
                        'platform': platform_name,
                        'handle': social_media_handle.replace('@', '') if social_media_handle else '',
                        'followers_count': followers_count,
                        'url': profile_url
                    }
                    social_platforms.append(platform_data)
                    
                    # Track the platform with the most followers as primary
                    if followers_count > primary_followers:
                        primary_platform = platform_name
                        primary_followers = followers_count
                
                # If no platforms were found, skip this row
                if not social_platforms:
                    error_count += 1
                    errors.append(f"Row {index+2}: No valid platform information found")
                    continue
                
                # Use the platform with the most followers as primary if available
                if not primary_platform:
                    primary_platform = social_platforms[0]['platform']
                
                # Create influencer data
                influencer_data = {
                    'name': row['name'],
                    'platform': primary_platform,
                    'followers_count': primary_followers,
                    'social_media_handle': next((p['handle'] for p in social_platforms if p['platform'] == primary_platform), ''),
                    'niche': row.get('niche', ''),
                    'region': row.get('region', ''),
                    'bio': row.get('bio', ''),
                    'demography': row.get('demography', ''),
                    'social_platforms': social_platforms
                }
                
                # Set social platform URLs
                for platform in social_platforms:
                    if platform['platform'] == 'Twitter':
                        influencer_data['twitter_url'] = platform['url']
                    elif platform['platform'] == 'Instagram':
                        influencer_data['instagram_url'] = platform['url']
                    elif platform['platform'] == 'TikTok':
                        influencer_data['tiktok_url'] = platform['url']
                    elif platform['platform'] == 'YouTube':
                        influencer_data['youtube_url'] = platform['url']
                
                # Create or update influencer
                influencer, created = Influencer.objects.update_or_create(
                    name=row['name'],
                    defaults=influencer_data
                )
                
                success_count += 1
                
            except Exception as e:
                error_count += 1
                errors.append(f"Row {index+2}: {str(e)}")
        
        return Response({
            'message': f'Successfully processed {success_count} influencers',
            'success_count': success_count,
            'error_count': error_count,
            'errors': errors[:10]  # Return first 10 errors only
        })
        
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['POST'])
def admin_login_view(request):
    try:
        username = request.data.get('username')
        password = request.data.get('password')
        
        if not all([username, password]):
            return Response({
                'error': 'Please provide username and password'
            }, status=400)
        
        user = authenticate(username=username, password=password)
                
        if user is not None and user.is_staff:  # Check if user is staff/admin
            refresh = RefreshToken.for_user(user)
            return Response({
                'token': str(refresh.access_token),
                'username': user.username,
                'message': 'Admin login successful'
            })
        else:
            return Response({
                'error': 'Invalid credentials or insufficient permissions'
            }, status=401)
    except Exception as e:
        print(f"Admin login error: {str(e)}")  # Add debug print
        return Response({
            'error': f'Server error: {str(e)}'
        }, status=500)
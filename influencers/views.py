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
    username = request.data.get("username")
    password = request.data.get("password")
    
    user = authenticate(username=username, password=password)
    if user:
        refresh = RefreshToken.for_user(user)
        return Response({
            "message": "Login successful",
            "role": user.profile.role,
            "token": str(refresh.access_token),
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email
            }
        }, status=200)
    return Response({"error": "Invalid credentials"}, status=400)

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
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import Booking
from .serializers import BookingSerializer

@api_view(['PATCH'])
def update_booking_status(request, booking_id):
    try:
        booking = Booking.objects.get(id=booking_id)
    except Booking.DoesNotExist:
        return Response({"error": "Booking not found"}, status=404)

    status = request.data.get("status")
    if status not in ["approved", "rejected"]:
        return Response({"error": "Invalid status"}, status=400)

    booking.status = status
    booking.save()

    return Response(BookingSerializer(booking).data, status=200)

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
            platforms = campaign.platforms if isinstance(campaign.platforms, list) else [campaign.platforms]
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
def influencer_profile(request, influencer_id):
    try:
        influencer = Influencer.objects.get(id=influencer_id)
        
        # Get campaign history
        campaign_history = Booking.objects.filter(
            influencer=influencer
        ).select_related('campaign').order_by('-created_at')
        
        data = {
            'id': influencer.id,
            'name': influencer.name,
            'platform': influencer.platform,
            'niche': influencer.niche,
            'followers_count': influencer.followers_count,
            'profile_picture': influencer.get_profile_picture(),
            'social_media_handle': influencer.social_media_handle,
            'interests': influencer.interests,
            'demography': influencer.demography,
            'instagram_url': influencer.instagram_url,
            'tiktok_url': influencer.tiktok_url,
            'youtube_url': influencer.youtube_url,
            'twitter_url': influencer.twitter_url,
            'engagement_rate': '4.5',
            'avg_likes': influencer.followers_count * 0.045,
            'avg_comments': influencer.followers_count * 0.002,
            'campaign_history': [{
                'name': booking.campaign.name,
                'duration': '30 days',
                'performance': 'Good',
                'status': booking.status
            } for booking in campaign_history]
        }
        return Response(data)
    except Influencer.DoesNotExist:
        return Response({'error': 'Influencer not found'}, status=404)
    except Exception as e:
        print(f"Error fetching influencer profile: {str(e)}")
        return Response({'error': str(e)}, status=500)

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

            serializer = self.get_serializer(instance, data=request.data, partial=True)
            
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
        data = request.data
        
        # Check if user already exists
        if User.objects.filter(username=data['username']).exists():
            return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)
        
        if User.objects.filter(email=data['email']).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Create user
        user = User.objects.create_user(
            username=data['username'],
            email=data['email'],
            password=data['password']
        )
        
        # Create profile with role
        Profile.objects.create(
            user=user,
            role=data['role']
        )
        
        return Response({'message': 'Registration successful'}, status=status.HTTP_201_CREATED)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

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
    try:
        print("Received data:", request.data)  # Debug log
        
        data = {
            'name': request.data.get('name'),
            'platform': request.data.get('platform'),
            'followers_count': request.data.get('followers_count'),
            'niche': request.data.get('niche'),
            'social_media_handle': request.data.get('social_media_handle'),
            'region': request.data.get('region', 'Nigeria'),
            'interests': request.data.get('interests'),
            'demography': request.data.get('demography'),
            # Add social media URLs
            'instagram_url': request.data.get('instagram_url'),
            'tiktok_url': request.data.get('tiktok_url'),
            'youtube_url': request.data.get('youtube_url'),
            'twitter_url': request.data.get('twitter_url'),
            'profile_picture': request.FILES.get('profile_picture')
        }

        serializer = InfluencerSerializer(data=data, context={'request': request})  # Add request context
        if serializer.is_valid():
            influencer = serializer.save()
            return Response({
                'message': 'Influencer added successfully',
                'influencer_id': influencer.id,
                'name': influencer.name,
                'platform': influencer.platform,
                'followers_count': influencer.followers_count,
                'niche': influencer.niche,
                'social_media_handle': influencer.social_media_handle,
                'region': influencer.region,
                'interests': influencer.interests,
                'demography': influencer.demography,
                'instagram_url': influencer.instagram_url,
                'tiktok_url': influencer.tiktok_url,
                'youtube_url': influencer.youtube_url,
                'twitter_url': influencer.twitter_url,
                'profile_picture': request.build_absolute_uri(influencer.profile_picture.url) if influencer.profile_picture else None
            }, status=status.HTTP_201_CREATED)
        
        print("Validation errors:", serializer.errors)  # Debug log
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    except Exception as e:
        print(f"Error in admin_add_influencer: {str(e)}")  # Debug log
        return Response(
            {'error': str(e)}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

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
        influencers = Influencer.objects.all()
        print("Influencers data:", [
            {
                'id': inf.id,
                'name': inf.name,
                'base_fee': inf.base_fee,
                'type': type(inf.base_fee)
            } 
            for inf in influencers
        ])  # Debug log
        serializer = InfluencerSerializer(influencers, many=True)
        return Response(serializer.data)
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
        print(f"Current base_fee: {influencer.base_fee}")  # Debug log
    except Influencer.DoesNotExist:
        return Response({'error': 'Influencer not found'}, status=404)

    try:
        print("Received data:", request.data)  # Debug incoming data
        print(f"Received base_fee: {request.data.get('base_fee')}")  # Debug base_fee specifically
        
        update_data = {
            'name': request.data.get('name'),
            'platform': request.data.get('platform'),
            'followers_count': request.data.get('followers_count'),
            'niche': request.data.get('niche'),
            'social_media_handle': request.data.get('social_media_handle'),
            'region': request.data.get('region'),
            'demography': request.data.get('demography'),
            'base_fee': request.data.get('base_fee'),
            'interests': request.data.get('interests', '')
        }
        
        serializer = InfluencerSerializer(influencer, data=update_data, partial=True)
        if serializer.is_valid():
            updated_influencer = serializer.save()
            print(f"Updated base_fee: {updated_influencer.base_fee}")  # Debug log after save
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
        
        print(f"Updating booking {pk} status to {new_status}")  # Debug log
        
        if new_status not in ['approved', 'rejected', 'pending', 'completed']:
            return Response(
                {'error': 'Invalid status'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        booking.status = new_status
        booking.save()

        # If booking is approved, create a notification
        if new_status == 'approved':
            if booking.campaign.owner:
                InfluencerNotification.objects.create(
                    influencer=booking.influencer,
                    message=f"Your booking for campaign '{booking.campaign.name}' has been approved. Please proceed with payment."
                )
                print(f"Created notification for booking {pk}")  # Debug log

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
        print(f"Error updating booking status: {str(e)}")  # Debug log
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
def admin_campaign_detail(request, campaign_id):
    try:
        campaign = Campaign.objects.get(id=campaign_id)
        data = {
            'id': campaign.id,
            'name': campaign.name,
            'objective': campaign.objective,
            'platforms': campaign.platforms,
            'budget': str(campaign.budget),
            'demography': campaign.demography,
            'gender': campaign.gender,
            'region': campaign.region,
            'industry': campaign.industry,
            'status': 'Active' if campaign.is_assigned else 'Pending',
            'created_at': campaign.created_at,
            'owner': {
                'id': campaign.owner.id,
                'username': campaign.owner.username,
                'email': campaign.owner.email
            } if campaign.owner else None
        }
        return Response(data)
    except Campaign.DoesNotExist:
        return Response({'error': 'Campaign not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

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
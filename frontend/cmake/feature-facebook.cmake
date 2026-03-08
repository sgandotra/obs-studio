if(
  FACEBOOK_CLIENTID
  AND FACEBOOK_SECRET
  AND FACEBOOK_CLIENTID_HASH MATCHES "^(0|[a-fA-F0-9]+)$"
  AND FACEBOOK_SECRET_HASH MATCHES "^(0|[a-fA-F0-9]+)$"
)
  target_sources(obs-studio PRIVATE oauth/FacebookAuth.cpp oauth/FacebookAuth.hpp)
  target_enable_feature(obs-studio "Facebook Live API connection" FACEBOOK_ENABLED)
else()
  target_disable_feature(obs-studio "Facebook Live API connection")
  set(FACEBOOK_CLIENTID_HASH 0)
  set(FACEBOOK_SECRET_HASH 0)
endif()

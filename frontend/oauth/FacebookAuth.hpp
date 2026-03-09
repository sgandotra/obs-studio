#pragma once

// FacebookAuth - OAuth integration for Facebook Live streaming.
//
// Extends OAuthStreamKey to implement the Facebook OAuth2 flow:
// - Login() launches an external browser for Facebook OAuth, listens for
//   the redirect via AuthListener, exchanges the auth code for a token,
//   then upgrades to a long-lived token (60-day expiry).
// - SaveInternal()/LoadInternal() persist the access token, expiry time,
//   and scope version to OBS config under the "Facebook" section.
// - GenerateState() creates a random state string for CSRF protection.
// - ExchangeForLongLivedToken() swaps a short-lived token for a
//   long-lived one via the Facebook Graph API.
// - LoadUI() is a stub for future UI additions (e.g. chat, dashboard).
//
// Registered via RegisterFacebookAuth() in FacebookAuth.cpp, which also
// handles cookie cleanup for facebook.com when the user disconnects.

#include "OAuth.hpp"

class FacebookAuth : public OAuthStreamKey {
	Q_OBJECT

	bool uiLoaded = false;

	virtual bool RetryLogin() override;
	virtual void SaveInternal() override;
	virtual bool LoadInternal() override;
	virtual void LoadUI() override;

	QString GenerateState();

	bool ExchangeForLongLivedToken(const std::string &client_id,
				       const std::string &secret);

public:
	FacebookAuth(const Def &d);
	~FacebookAuth();

	static std::shared_ptr<Auth> Login(QWidget *parent,
					   const std::string &service);
};

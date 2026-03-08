#pragma once

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

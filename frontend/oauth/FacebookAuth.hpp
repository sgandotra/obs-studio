#pragma once

#include "OAuth.hpp"

#include <QDialog>
#include <QTimer>

class QLabel;
class QPushButton;
class QProgressBar;

/* ------------------------------------------------------------------ */
/* FacebookDeviceDialog — custom dialog for Device Authorization Flow */
/* ------------------------------------------------------------------ */

class FacebookDeviceDialog : public QDialog {
	Q_OBJECT

	QLabel *codeLabel = nullptr;
	QLabel *instructionLabel = nullptr;
	QPushButton *copyButton = nullptr;
	QPushButton *cancelButton = nullptr;
	QProgressBar *expiryBar = nullptr;
	QTimer pollTimer;
	QTimer expiryTimer;

	std::string deviceCode;
	std::string appToken;
	int pollInterval = 5;
	int expirySeconds = 0;
	int elapsedSeconds = 0;

	void PollForToken();
	void OnExpiryTick();

public:
	FacebookDeviceDialog(QWidget *parent, const std::string &userCode,
			     const std::string &verificationUri,
			     const std::string &deviceCode,
			     const std::string &appToken, int interval,
			     int expiresIn);
	~FacebookDeviceDialog();

	std::string resultToken;
	uint64_t resultExpireTime = 0;

signals:
	void TokenReceived();
};

/* ------------------------------------------------------------------ */
/* FacebookAuth                                                       */
/* ------------------------------------------------------------------ */

class FacebookAuth : public OAuthStreamKey {
	Q_OBJECT

	bool uiLoaded = false;
	QTimer refreshTimer;

	virtual bool RetryLogin() override;
	virtual void SaveInternal() override;
	virtual bool LoadInternal() override;
	virtual void LoadUI() override;

	bool ExchangeForLongLivedToken(const std::string &appToken);
	void ScheduleTokenRefresh();

public:
	FacebookAuth(const Def &d);
	~FacebookAuth();

	static std::shared_ptr<Auth> Login(QWidget *parent,
					   const std::string &service);
};

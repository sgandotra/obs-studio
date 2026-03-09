#include "FacebookAuth.hpp"

#include <utility/obf.h>
#include <utility/RemoteTextThread.hpp>
#include <widgets/OBSBasic.hpp>

#ifdef BROWSER_AVAILABLE
#include <browser-panel.hpp>
#endif
#include <qt-wrappers.hpp>
#include <ui-config.h>

#include <QApplication>
#include <QClipboard>
#include <QDesktopServices>
#include <QHBoxLayout>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QUrl>
#include <QVBoxLayout>

#include <json11.hpp>

#include "moc_FacebookAuth.cpp"

using namespace json11;

/* Facebook Graph API v19.0 Device Login endpoints */
#define FACEBOOK_DEVICE_LOGIN_URL \
	"https://graph.facebook.com/v19.0/device/login"
#define FACEBOOK_DEVICE_LOGIN_STATUS_URL \
	"https://graph.facebook.com/v19.0/device/login_status"
#define FACEBOOK_TOKEN_URL \
	"https://graph.facebook.com/v19.0/oauth/access_token"

#define FACEBOOK_SCOPE_VERSION 1
#define SECTION_NAME "Facebook"

static Auth::Def facebookDef = {"Facebook Live",
				Auth::Type::OAuth_StreamKey, true, false};

/* ========================================================================= */
/* FacebookDeviceDialog                                                      */
/* ========================================================================= */

FacebookDeviceDialog::FacebookDeviceDialog(QWidget *parent,
					   const std::string &userCode,
					   const std::string &verificationUri,
					   const std::string &deviceCode_,
					   const std::string &appToken_,
					   int interval, int expiresIn)
	: QDialog(parent),
	  deviceCode(deviceCode_),
	  appToken(appToken_),
	  pollInterval(interval > 0 ? interval : 5),
	  expirySeconds(expiresIn)
{
	setWindowTitle(QTStr("Facebook.Auth.DeviceLogin.Title"));
	setMinimumWidth(420);
	setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);

	auto *layout = new QVBoxLayout(this);
	layout->setSpacing(12);

	/* Instruction text */
	instructionLabel = new QLabel(this);
	instructionLabel->setWordWrap(true);
	instructionLabel->setTextFormat(Qt::RichText);
	instructionLabel->setOpenExternalLinks(true);

	QString uri = QString::fromStdString(verificationUri);
	instructionLabel->setText(
		QTStr("Facebook.Auth.DeviceLogin.Instruction")
			.arg(QString("<a href='%1'>%1</a>").arg(uri)));
	layout->addWidget(instructionLabel);

	/* User code — displayed large and prominent */
	codeLabel = new QLabel(QString::fromStdString(userCode), this);
	QFont codeFont = codeLabel->font();
	codeFont.setPointSize(28);
	codeFont.setBold(true);
	codeFont.setLetterSpacing(QFont::AbsoluteSpacing, 4);
	codeLabel->setFont(codeFont);
	codeLabel->setAlignment(Qt::AlignCenter);
	codeLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
	codeLabel->setStyleSheet(
		"QLabel { background: palette(base); border: 1px solid "
		"palette(mid); border-radius: 6px; padding: 16px; }");
	layout->addWidget(codeLabel);

	/* Copy button */
	auto *buttonRow = new QHBoxLayout();
	copyButton = new QPushButton(
		QTStr("Facebook.Auth.DeviceLogin.CopyCode"), this);
	connect(copyButton, &QPushButton::clicked, this, [userCode]() {
		QApplication::clipboard()->setText(
			QString::fromStdString(userCode));
	});
	buttonRow->addStretch();
	buttonRow->addWidget(copyButton);
	buttonRow->addStretch();
	layout->addLayout(buttonRow);

	/* Expiry progress bar */
	expiryBar = new QProgressBar(this);
	expiryBar->setRange(0, expirySeconds);
	expiryBar->setValue(expirySeconds);
	expiryBar->setTextVisible(false);
	expiryBar->setFixedHeight(6);
	layout->addWidget(expiryBar);

	/* Status label */
	auto *statusLabel = new QLabel(
		QTStr("Facebook.Auth.DeviceLogin.Waiting"), this);
	statusLabel->setAlignment(Qt::AlignCenter);
	layout->addWidget(statusLabel);

	/* Cancel button */
	cancelButton = new QPushButton(QTStr("Cancel"), this);
	connect(cancelButton, &QPushButton::clicked, this, &QDialog::reject);
	auto *cancelRow = new QHBoxLayout();
	cancelRow->addStretch();
	cancelRow->addWidget(cancelButton);
	layout->addLayout(cancelRow);

	setLayout(layout);

	/* Start polling timer */
	connect(&pollTimer, &QTimer::timeout, this,
		&FacebookDeviceDialog::PollForToken);
	pollTimer.start(pollInterval * 1000);

	/* Start expiry countdown timer */
	connect(&expiryTimer, &QTimer::timeout, this,
		&FacebookDeviceDialog::OnExpiryTick);
	expiryTimer.start(1000);
}

FacebookDeviceDialog::~FacebookDeviceDialog()
{
	pollTimer.stop();
	expiryTimer.stop();
}

void FacebookDeviceDialog::PollForToken()
{
	std::string post_data;
	post_data += "access_token=";
	post_data += appToken;
	post_data += "&code=";
	post_data += deviceCode;

	std::string output;
	std::string error;

	bool success = GetRemoteFile(
		FACEBOOK_DEVICE_LOGIN_STATUS_URL, output, error, nullptr,
		"application/x-www-form-urlencoded", "", post_data.c_str(),
		std::vector<std::string>(), nullptr, 5);

	if (!success || output.empty())
		return;

	std::string parse_error;
	Json json = Json::parse(output, parse_error);
	if (!parse_error.empty())
		return;

	/* Check for pending/errors */
	auto errObj = json["error"];
	if (errObj.is_object()) {
		int subcode = errObj["error_subcode"].int_value();
		/* 1349174 = authorization_pending — keep polling */
		if (subcode == 1349174)
			return;
		/* 1349172 = code_expired */
		if (subcode == 1349172) {
			reject();
			return;
		}
		/* 1349152 = slow_down — increase interval */
		if (subcode == 1349152) {
			pollInterval += 2;
			pollTimer.setInterval(pollInterval * 1000);
			return;
		}
		/* Any other error — abort */
		blog(LOG_WARNING,
		     "FacebookDeviceDialog: poll error: %s (subcode %d)",
		     errObj["message"].string_value().c_str(), subcode);
		reject();
		return;
	}

	/* Success — we have an access token */
	resultToken = json["access_token"].string_value();
	int expiresIn = json["expires_in"].int_value();
	if (expiresIn > 0)
		resultExpireTime = (uint64_t)time(nullptr) + expiresIn;

	if (!resultToken.empty()) {
		pollTimer.stop();
		expiryTimer.stop();
		emit TokenReceived();
		accept();
	}
}

void FacebookDeviceDialog::OnExpiryTick()
{
	elapsedSeconds++;
	int remaining = expirySeconds - elapsedSeconds;
	if (remaining <= 0) {
		expiryTimer.stop();
		pollTimer.stop();
		reject();
		return;
	}
	expiryBar->setValue(remaining);
}

/* ========================================================================= */
/* FacebookAuth                                                              */
/* ========================================================================= */

static void DeleteCookies()
{
#ifdef BROWSER_AVAILABLE
	extern QCefCookieManager *panel_cookies;
	if (panel_cookies)
		panel_cookies->DeleteCookies("facebook.com", "");
#endif
}

void RegisterFacebookAuth()
{
#if !defined(__APPLE__) && !defined(_WIN32)
	if (QApplication::platformName().contains("wayland"))
		return;
#endif

	OAuth::RegisterOAuth(
		facebookDef,
		[]() { return std::make_shared<FacebookAuth>(facebookDef); },
		FacebookAuth::Login, DeleteCookies);
}

FacebookAuth::FacebookAuth(const Def &d) : OAuthStreamKey(d)
{
	connect(&refreshTimer, &QTimer::timeout, this,
		&FacebookAuth::ScheduleTokenRefresh);
}

FacebookAuth::~FacebookAuth()
{
	refreshTimer.stop();
}

bool FacebookAuth::RetryLogin()
{
	return true;
}

void FacebookAuth::SaveInternal()
{
	OBSBasic *main = OBSBasic::Get();
	config_set_string(main->Config(), SECTION_NAME, "Token",
			  token.c_str());
	config_set_uint(main->Config(), SECTION_NAME, "ExpireTime",
			expire_time);
	config_set_int(main->Config(), SECTION_NAME, "ScopeVer",
		       currentScopeVer);
}

static inline std::string get_config_str(OBSBasic *main, const char *section,
					  const char *name)
{
	const char *val = config_get_string(main->Config(), section, name);
	return val ? val : "";
}

bool FacebookAuth::LoadInternal()
{
	OBSBasic *main = OBSBasic::Get();
	token = get_config_str(main, SECTION_NAME, "Token");
	expire_time =
		config_get_uint(main->Config(), SECTION_NAME, "ExpireTime");
	currentScopeVer =
		(int)config_get_int(main->Config(), SECTION_NAME, "ScopeVer");
	firstLoad = false;

	if (!token.empty())
		ScheduleTokenRefresh();

	return !token.empty();
}

void FacebookAuth::LoadUI()
{
	if (uiLoaded)
		return;
	uiLoaded = true;
}

void FacebookAuth::ScheduleTokenRefresh()
{
	if (expire_time == 0)
		return;

	uint64_t now = (uint64_t)time(nullptr);
	if (now >= expire_time) {
		blog(LOG_WARNING,
		     "FacebookAuth: Token already expired, "
		     "user must re-authenticate");
		return;
	}

	/* Refresh 24 hours before expiry, or halfway if less than 48h left */
	uint64_t remaining = expire_time - now;
	uint64_t refreshIn;
	if (remaining > 48 * 3600)
		refreshIn = remaining - 24 * 3600;
	else
		refreshIn = remaining / 2;

	refreshTimer.setSingleShot(true);
	refreshTimer.start((int)(refreshIn * 1000));

	blog(LOG_INFO,
	     "FacebookAuth: Token refresh scheduled in %llu seconds",
	     (unsigned long long)refreshIn);
}

bool FacebookAuth::ExchangeForLongLivedToken(const std::string &appToken)
{
	/* Extract client_id and secret from the app token (format: id|secret) */
	size_t pipe = appToken.find('|');
	if (pipe == std::string::npos)
		return false;

	std::string client_id = appToken.substr(0, pipe);
	std::string secret = appToken.substr(pipe + 1);

	std::string url = FACEBOOK_TOKEN_URL;
	std::string post_data;
	post_data += "grant_type=fb_exchange_token";
	post_data += "&client_id=";
	post_data += client_id;
	post_data += "&client_secret=";
	post_data += secret;
	post_data += "&fb_exchange_token=";
	post_data += token;

	std::string output;
	std::string error;
	bool success = false;

	auto func = [&]() {
		success = GetRemoteFile(
			url.c_str(), output, error, nullptr,
			"application/x-www-form-urlencoded", "",
			post_data.c_str(), std::vector<std::string>(), nullptr,
			5);
	};

	ExecThreadedWithoutBlocking(
		func, QTStr("Auth.Authing.Title"),
		QTStr("Facebook.Auth.TokenExchange"));

	if (!success || output.empty()) {
		blog(LOG_WARNING,
		     "FacebookAuth::ExchangeForLongLivedToken: "
		     "Failed to exchange token: %s",
		     error.c_str());
		return false;
	}

	std::string parse_error;
	Json json = Json::parse(output, parse_error);
	if (!parse_error.empty()) {
		blog(LOG_WARNING,
		     "FacebookAuth::ExchangeForLongLivedToken: "
		     "Failed to parse response: %s",
		     parse_error.c_str());
		return false;
	}

	std::string err = json["error"]["message"].string_value();
	if (!err.empty()) {
		blog(LOG_WARNING,
		     "FacebookAuth::ExchangeForLongLivedToken: "
		     "API error: %s",
		     err.c_str());
		return false;
	}

	std::string new_token = json["access_token"].string_value();
	if (new_token.empty()) {
		blog(LOG_WARNING,
		     "FacebookAuth::ExchangeForLongLivedToken: "
		     "No access_token in response");
		return false;
	}

	token = new_token;
	int expires_in = json["expires_in"].int_value();
	if (expires_in > 0)
		expire_time = (uint64_t)time(nullptr) + expires_in;

	return true;
}

/* static */
std::shared_ptr<Auth> FacebookAuth::Login(QWidget *owner,
					   const std::string &service)
{
	if (service != facebookDef.service)
		return nullptr;

	auto auth = std::make_shared<FacebookAuth>(facebookDef);

	/* Build the app access token: APP_ID|APP_SECRET */
	std::string clientid = FACEBOOK_CLIENTID;
	std::string secret = FACEBOOK_SECRET;
	deobfuscate_str(&clientid[0], FACEBOOK_CLIENTID_HASH);
	deobfuscate_str(&secret[0], FACEBOOK_SECRET_HASH);

	std::string appToken = clientid + "|" + secret;

	/* Step 1: Request a device code from Facebook */
	std::string post_data;
	post_data += "access_token=";
	post_data += appToken;
	post_data += "&scope=publish_video";

	std::string output;
	std::string error;
	bool success = false;

	auto func = [&]() {
		success = GetRemoteFile(
			FACEBOOK_DEVICE_LOGIN_URL, output, error, nullptr,
			"application/x-www-form-urlencoded", "",
			post_data.c_str(), std::vector<std::string>(), nullptr,
			5);
	};

	ExecThreadedWithoutBlocking(func, QTStr("Auth.Authing.Title"),
				    QTStr("Facebook.Auth.DeviceLogin.Init"));

	if (!success || output.empty()) {
		blog(LOG_WARNING,
		     "FacebookAuth::Login: Failed to request device code: %s",
		     error.c_str());
		return nullptr;
	}

	std::string parse_error;
	Json json = Json::parse(output, parse_error);
	if (!parse_error.empty()) {
		blog(LOG_WARNING,
		     "FacebookAuth::Login: Failed to parse device code "
		     "response: %s",
		     parse_error.c_str());
		return nullptr;
	}

	std::string err = json["error"]["message"].string_value();
	if (!err.empty()) {
		blog(LOG_WARNING, "FacebookAuth::Login: API error: %s",
		     err.c_str());
		return nullptr;
	}

	std::string userCode = json["user_code"].string_value();
	std::string deviceCode = json["code"].string_value();
	std::string verificationUri =
		json["verification_uri"].string_value();
	int interval = json["interval"].int_value();
	int expiresIn = json["expires_in"].int_value();

	if (userCode.empty() || deviceCode.empty()) {
		blog(LOG_WARNING,
		     "FacebookAuth::Login: Missing user_code or device code "
		     "in response");
		return nullptr;
	}

	/* Step 2: Show the Device Dialog and poll for authorization */
	FacebookDeviceDialog dlg(owner, userCode, verificationUri, deviceCode,
				 appToken, interval, expiresIn);

#if defined(__APPLE__) && QT_VERSION >= QT_VERSION_CHECK(6, 5, 0) && \
	QT_VERSION < QT_VERSION_CHECK(6, 6, 0)
	const bool nativeDialogs =
		qApp->testAttribute(Qt::AA_DontUseNativeDialogs);
	App()->setAttribute(Qt::AA_DontUseNativeDialogs, true);
	dlg.exec();
	App()->setAttribute(Qt::AA_DontUseNativeDialogs, nativeDialogs);
#else
	dlg.exec();
#endif

	if (dlg.result() != QDialog::Accepted || dlg.resultToken.empty())
		return nullptr;

	/* Step 3: Store the short-lived token */
	auth->token = dlg.resultToken;
	auth->expire_time = dlg.resultExpireTime;
	auth->currentScopeVer = FACEBOOK_SCOPE_VERSION;

	/* Step 4: Exchange for long-lived token (60 days) */
	if (!auth->ExchangeForLongLivedToken(appToken)) {
		blog(LOG_WARNING,
		     "FacebookAuth: Failed to exchange for long-lived token, "
		     "continuing with short-lived token");
	}

	/* Step 5: Schedule proactive refresh */
	auth->ScheduleTokenRefresh();

	config_t *config = OBSBasic::Get()->Config();
	config_save_safe(config, "tmp", nullptr);
	return auth;
}

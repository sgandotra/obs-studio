#include "FacebookAuth.hpp"

#include <oauth/AuthListener.hpp>
#include <utility/obf.h>
#include <utility/RemoteTextThread.hpp>
#include <widgets/OBSBasic.hpp>

#include <qt-wrappers.hpp>
#include <ui-config.h>

#include <QDesktopServices>
#include <QRandomGenerator>

#include <json11.hpp>

#include "moc_FacebookAuth.cpp"

using namespace json11;

#define FACEBOOK_AUTH_URL "https://www.facebook.com/v19.0/dialog/oauth"
#define FACEBOOK_TOKEN_URL "https://graph.facebook.com/v19.0/oauth/access_token"
#define FACEBOOK_SCOPE_VERSION 1
#define FACEBOOK_API_STATE_LENGTH 32
#define SECTION_NAME "Facebook"

static const char allowedChars[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
static const int allowedCount = static_cast<int>(sizeof(allowedChars) - 1);

static Auth::Def facebookDef = {"Facebook Live",
				Auth::Type::OAuth_StreamKey, true, false};

/* ------------------------------------------------------------------------- */

static inline void OpenBrowser(const QString auth_uri)
{
	QUrl url(auth_uri, QUrl::StrictMode);
	QDesktopServices::openUrl(url);
}

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
	OAuth::RegisterOAuth(
		facebookDef,
		[]() { return std::make_shared<FacebookAuth>(facebookDef); },
		FacebookAuth::Login, DeleteCookies);
}

FacebookAuth::FacebookAuth(const Def &d) : OAuthStreamKey(d) {}

FacebookAuth::~FacebookAuth() {}

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
	return !token.empty();
}

void FacebookAuth::LoadUI()
{
	if (uiLoaded)
		return;
	uiLoaded = true;
}

QString FacebookAuth::GenerateState()
{
	char state[FACEBOOK_API_STATE_LENGTH + 1];
	QRandomGenerator *rng = QRandomGenerator::system();
	int i;

	for (i = 0; i < FACEBOOK_API_STATE_LENGTH; i++)
		state[i] = allowedChars[rng->bounded(0, allowedCount)];
	state[i] = 0;

	return state;
}

bool FacebookAuth::ExchangeForLongLivedToken(const std::string &client_id,
					      const std::string &secret)
{
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

// Static.
std::shared_ptr<Auth> FacebookAuth::Login(QWidget *owner,
					   const std::string &service)
{
	QString auth_code;
	AuthListener server;

	if (service != facebookDef.service)
		return nullptr;

	auto auth = std::make_shared<FacebookAuth>(facebookDef);

	QString redirect_uri =
		QString("http://127.0.0.1:%1").arg(server.GetPort());

	QMessageBox dlg(owner);
	dlg.setWindowFlags(dlg.windowFlags() & ~Qt::WindowCloseButtonHint);
	dlg.setWindowTitle(QTStr("Facebook.Auth.WaitingAuth.Title"));

	std::string clientid = FACEBOOK_CLIENTID;
	std::string secret = FACEBOOK_SECRET;
	deobfuscate_str(&clientid[0], FACEBOOK_CLIENTID_HASH);
	deobfuscate_str(&secret[0], FACEBOOK_SECRET_HASH);

	QString state;
	state = auth->GenerateState();
	server.SetState(state);

	QString url_template;
	url_template += "%1";
	url_template += "?response_type=code";
	url_template += "&client_id=%2";
	url_template += "&redirect_uri=%3";
	url_template += "&state=%4";
	url_template += "&scope=publish_video";
	QString url = url_template.arg(FACEBOOK_AUTH_URL, clientid.c_str(),
				       redirect_uri, state);

	QString text = QTStr("Facebook.Auth.WaitingAuth.Text");
	text = text.arg(
		QString("<a href='%1'>Facebook OAuth Service</a>").arg(url));

	dlg.setText(text);
	dlg.setTextFormat(Qt::RichText);
	dlg.setStandardButtons(QMessageBox::StandardButton::Cancel);
#if defined(__APPLE__) && QT_VERSION >= QT_VERSION_CHECK(6, 6, 0)
	dlg.setOption(QMessageBox::Option::DontUseNativeDialog);
#endif

	connect(&dlg, &QMessageBox::buttonClicked, &dlg,
		[&](QAbstractButton *) {
#ifdef _DEBUG
			blog(LOG_DEBUG, "Action Cancelled.");
#endif
			dlg.reject();
		});

	// Async Login.
	connect(&server, &AuthListener::ok, &dlg,
		[&dlg, &auth_code](QString code) {
#ifdef _DEBUG
			blog(LOG_DEBUG,
			     "Got facebook redirected answer: %s",
			     QT_TO_UTF8(code));
#endif
			auth_code = code;
			dlg.accept();
		});
	connect(&server, &AuthListener::fail, &dlg, [&dlg]() {
#ifdef _DEBUG
		blog(LOG_DEBUG, "No access granted");
#endif
		dlg.reject();
	});

	auto open_external_browser = [url]() { OpenBrowser(url); };
	QScopedPointer<QThread> thread(CreateQThread(open_external_browser));
	thread->start();

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

	if (dlg.result() == QMessageBox::Cancel ||
	    dlg.result() == QDialog::Rejected)
		return nullptr;

	if (!auth->GetToken(FACEBOOK_TOKEN_URL, clientid, secret,
			    QT_TO_UTF8(redirect_uri), FACEBOOK_SCOPE_VERSION,
			    QT_TO_UTF8(auth_code), true)) {
		return nullptr;
	}

	/* Exchange short-lived token for long-lived token (60 days) */
	if (!auth->ExchangeForLongLivedToken(clientid, secret)) {
		blog(LOG_WARNING,
		     "FacebookAuth: Failed to exchange for long-lived token, "
		     "continuing with short-lived token");
	}

	config_t *config = OBSBasic::Get()->Config();
	config_save_safe(config, "tmp", nullptr);
	return auth;
}

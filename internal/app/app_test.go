package protectorapp

import (
	"context"
	"testing"

	api "github.com/AlexeyInc/Brute-force-protector/api/protoc"
	protectorconfig "github.com/AlexeyInc/Brute-force-protector/configs"
	constant "github.com/AlexeyInc/Brute-force-protector/internal/constants"
	memorystorage "github.com/AlexeyInc/Brute-force-protector/internal/storage/memory"
	"github.com/AlexeyInc/Brute-force-protector/util"
	"github.com/stretchr/testify/require"
)

var configFile = "../../configs/bf-protector_config.toml"

const (
	_testIP             = "testIP"
	_allowRequestsCount = 5
)

type senderCred struct {
	login    string
	password string
}

type bruteForceLimits struct {
	ip       int
	login    int
	password int
}

func TestAuthorization(t *testing.T) {
	config, err := protectorconfig.NewConfig(configFile)
	if err != nil {
		require.NoError(t, err)
	}

	storage := memorystorage.New()
	defer storage.Close()

	app := New(config, storage)
	app.getIPFromContext = getSenderTestIP

	ctx := context.Background()
	err = storage.Seed(ctx,
		[]string{constant.WhiteIPsKey, constant.BlackIPsKey},
		[][]string{getWhiteListIPs(), getBlackListIPs()},
	)
	if err != nil {
		require.NoError(t, err)
	}

	bruteForceTests := []struct {
		name       string
		senderData senderCred
		limits     bruteForceLimits
	}{
		{
			name:       "detect brute force on login",
			senderData: senderCred{util.RandomLogin(), util.RandomPassword()},
			limits: bruteForceLimits{
				ip:       _allowRequestsCount + 1,
				login:    _allowRequestsCount,
				password: _allowRequestsCount + 1},
		},
		{
			name:       "detect brute force on password",
			senderData: senderCred{util.RandomLogin(), util.RandomPassword()},
			limits: bruteForceLimits{
				ip:       _allowRequestsCount + 1,
				login:    _allowRequestsCount + 1,
				password: _allowRequestsCount},
		},
		{
			name:       "detect brute force on ip",
			senderData: senderCred{util.RandomLogin(), util.RandomPassword()},
			limits: bruteForceLimits{
				ip:       _allowRequestsCount,
				login:    _allowRequestsCount + 1,
				password: _allowRequestsCount + 1},
		},
	}
	for _, bftest := range bruteForceTests {
		t.Run(bftest.name, func(t *testing.T) {
			resetAppContext(app, storage, bftest.senderData, bftest.limits)
			defer finalizeApp(app, storage)

			testLogin := &api.Login{
				Login:    bftest.senderData.login,
				Password: bftest.senderData.password,
			}
			extraRequestForBruteFroceCheck(t, context.Background(), app, testLogin)
		})
	}

	blackwhiteListTests := []struct {
		name           string
		senderData     senderCred
		limits         bruteForceLimits
		senderIP       func(context.Context) (string, error)
		expectedResult bool
		message        string
	}{
		{
			name:           "detect IP from white list",
			senderData:     senderCred{util.RandomLogin(), util.RandomPassword()},
			limits:         bruteForceLimits{_allowRequestsCount, _allowRequestsCount, _allowRequestsCount},
			senderIP:       randWhiteIP,
			expectedResult: true,
			message:        _whiteListIPText,
		},
		{
			name:           "detect IP from black list",
			senderData:     senderCred{util.RandomLogin(), util.RandomPassword()},
			limits:         bruteForceLimits{_allowRequestsCount, _allowRequestsCount, _allowRequestsCount},
			senderIP:       randBlackIP,
			expectedResult: false,
			message:        _blackListIPText,
		},
	}
	for _, wbltest := range blackwhiteListTests {
		t.Run(wbltest.name, func(t *testing.T) {
			resetAppContext(app, storage, wbltest.senderData, wbltest.limits)
			defer finalizeApp(app, storage)

			app.getIPFromContext = wbltest.senderIP

			testLogin := &api.Login{
				Login:    wbltest.senderData.login,
				Password: wbltest.senderData.password,
			}
			whiteBlackListCheck(t, ctx, app, testLogin, wbltest.expectedResult, wbltest.message)
		})
	}

	t.Run("handle error during brute-force check", func(t *testing.T) {
		finalizeApp(app, storage)

		login := &api.Login{
			Login:    util.RandomLogin(),
			Password: util.RandomPassword(),
		}

		resp, err := simulateRequestWithContext(app.Authorization, context.Background(), login)

		require.Error(t, err)
		require.Equal(t, false, resp.Success)
		require.Equal(t, _bruteForceCheckErr, resp.Msg)
	})
}

func extraRequestForBruteFroceCheck(t *testing.T, context context.Context, app *App, login *api.Login) {
	t.Helper()
	for i := 0; i < _allowRequestsCount; i++ {
		resp, err := simulateRequestWithContext(app.Authorization, context, login)
		require.NoError(t, err)
		require.Equal(t, true, resp.Success)
	}
	resp, err := simulateRequestWithContext(app.Authorization, context, login)
	require.NoError(t, err)
	require.Equal(t, false, resp.Success)
	require.Equal(t, _limitExceededText, resp.Msg)
}

func whiteBlackListCheck(t *testing.T, context context.Context, app *App, login *api.Login, expectedRes bool, expectedMsg string) {
	t.Helper()
	for i := 0; i < _allowRequestsCount; i++ {
		resp, err := app.Authorization(context, login)

		require.NoError(t, err)
		require.Equal(t, expectedRes, resp.Success)
		require.Equal(t, expectedMsg, resp.Msg)
	}
}

func resetAppContext(app *App, storage *memorystorage.MemoryStorage, s senderCred, limits bruteForceLimits) {
	memorystorage.ContextDoneCh = make(chan struct{})

	app.config.AttemptsLimit.IpRequestsMinute = limits.ip
	app.config.AttemptsLimit.LoginRequestsMinute = limits.login
	app.config.AttemptsLimit.PasswordRequestsMinute = limits.password

	storage.AddBruteForceLimit(_testIP, limits.ip)
	storage.AddBruteForceLimit(s.login, limits.login)
	storage.AddBruteForceLimit(s.password, limits.password)
}

func finalizeApp(app *App, storage *memorystorage.MemoryStorage) {
	app.getIPFromContext = getSenderTestIP
	storage.ResetStorage()
}

func simulateRequestWithContext(f func(context.Context, *api.Login) (*api.StatusResponse, error), ctx context.Context, login *api.Login) (*api.StatusResponse, error) {
	memorystorage.RequestContextWG.Add(constant.AttackTypesCount)
	resp, err := f(ctx, login)
	memorystorage.RequestContextWG.Wait()
	return resp, err
}

func getSenderTestIP(context.Context) (string, error) {
	return _testIP, nil
}

func randWhiteIP(context.Context) (string, error) {
	whiteIPs := getWhiteListIPs()
	return whiteIPs[util.RandomIntRange(0, len(whiteIPs)-1)], nil
}
func randBlackIP(context.Context) (string, error) {
	blackIPs := getBlackListIPs()
	return blackIPs[util.RandomIntRange(0, len(blackIPs)-1)], nil
}

func getWhiteListIPs() []string {
	return []string{"whiteIP_1", "whiteIP_2", "whiteIP_3"}
}

func getBlackListIPs() []string {
	return []string{"blackIP_1", "blackIP_2", "blackIP_3"}
}

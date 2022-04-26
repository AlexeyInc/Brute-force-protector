package protectorapp

// TODO: add test with some shity data and handle errors

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
	ip       string
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
			senderData: senderCred{util.RandomLogin(), util.RandomPassword(), util.RandomIP()},
			limits: bruteForceLimits{
				ip:       _allowRequestsCount + 1,
				login:    _allowRequestsCount,
				password: _allowRequestsCount + 1},
		},
		{
			name:       "detect brute force on password",
			senderData: senderCred{util.RandomLogin(), util.RandomPassword(), util.RandomIP()},
			limits: bruteForceLimits{
				ip:       _allowRequestsCount + 1,
				login:    _allowRequestsCount + 1,
				password: _allowRequestsCount},
		},
		{
			name:       "detect brute force on ip",
			senderData: senderCred{util.RandomLogin(), util.RandomPassword(), util.RandomIP()},
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

			testLogin := &api.AuthRequest{
				Login:    bftest.senderData.login,
				Password: bftest.senderData.password,
				Ip:       bftest.senderData.ip,
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
			senderData:     senderCred{util.RandomLogin(), util.RandomPassword(), randWhiteIP()},
			limits:         bruteForceLimits{_allowRequestsCount, _allowRequestsCount, _allowRequestsCount},
			expectedResult: true,
			message:        constant.WhiteListIpText,
		},
		{
			name:           "detect IP from black list",
			senderData:     senderCred{util.RandomLogin(), util.RandomPassword(), randBlackIP()},
			limits:         bruteForceLimits{_allowRequestsCount, _allowRequestsCount, _allowRequestsCount},
			expectedResult: false,
			message:        constant.BlackListIpText,
		},
	}
	for _, wbltest := range blackwhiteListTests {
		t.Run(wbltest.name, func(t *testing.T) {
			resetAppContext(app, storage, wbltest.senderData, wbltest.limits)
			defer finalizeApp(app, storage)

			testLogin := &api.AuthRequest{
				Login:    wbltest.senderData.login,
				Password: wbltest.senderData.password,
				Ip:       wbltest.senderData.ip,
			}
			whiteBlackListCheck(t, ctx, app, testLogin, wbltest.expectedResult, wbltest.message)
		})
	}

	t.Run("handle error during brute-force check", func(t *testing.T) {
		finalizeApp(app, storage)

		login := &api.AuthRequest{
			Login:    util.RandomLogin(),
			Password: util.RandomPassword(),
			Ip:       util.RandomIP(),
		}

		resp, err := simulateRequestWithContext(app.Authorization, context.Background(), login)

		require.Error(t, err)
		require.Equal(t, false, resp.Success)
		require.Equal(t, "", resp.Msg)
	})
}

func extraRequestForBruteFroceCheck(t *testing.T, context context.Context, app *App, login *api.AuthRequest) {
	t.Helper()
	for i := 0; i < _allowRequestsCount; i++ {
		resp, err := simulateRequestWithContext(app.Authorization, context, login)
		require.NoError(t, err)
		require.Equal(t, true, resp.Success)
	}
	resp, err := simulateRequestWithContext(app.Authorization, context, login)
	require.NoError(t, err)
	require.Equal(t, false, resp.Success)
	require.Equal(t, constant.LimitExceededText, resp.Msg)
}

func whiteBlackListCheck(t *testing.T, context context.Context, app *App, login *api.AuthRequest, expectedRes bool, expectedMsg string) {
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

	storage.AddBruteForceLimit(s.ip, limits.ip)
	storage.AddBruteForceLimit(s.login, limits.login)
	storage.AddBruteForceLimit(s.password, limits.password)
}

func finalizeApp(app *App, storage *memorystorage.MemoryStorage) {
	storage.ResetStorage()
}

func simulateRequestWithContext(f func(context.Context, *api.AuthRequest) (*api.StatusResponse, error), ctx context.Context, login *api.AuthRequest) (*api.StatusResponse, error) {
	memorystorage.RequestContextWG.Add(constant.AttackTypesCount)
	resp, err := f(ctx, login)
	memorystorage.RequestContextWG.Wait()
	return resp, err
}

func randWhiteIP() string {
	whiteIPs := getWhiteListIPs()
	return whiteIPs[util.RandomIntRange(0, len(whiteIPs)-1)]
}
func randBlackIP() string {
	blackIPs := getBlackListIPs()
	return blackIPs[util.RandomIntRange(0, len(blackIPs)-1)]
}

func getWhiteListIPs() []string {
	return []string{"whiteIP_1", "whiteIP_2", "whiteIP_3"}
}

func getBlackListIPs() []string {
	return []string{"blackIP_1", "blackIP_2", "blackIP_3"}
}

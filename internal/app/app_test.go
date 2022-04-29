package protectorapp

// TODO: add test with some shity data and handle errors

import (
	"context"
	"testing"

	api "github.com/AlexeyInc/Brute-force-protector/api/protoc"
	embed "github.com/AlexeyInc/Brute-force-protector/assets"
	protectorconfig "github.com/AlexeyInc/Brute-force-protector/configs"
	constant "github.com/AlexeyInc/Brute-force-protector/internal/constants"
	memorystorage "github.com/AlexeyInc/Brute-force-protector/internal/storage/memory"
	"github.com/AlexeyInc/Brute-force-protector/util"
	"github.com/stretchr/testify/require"
)

var configFile = "../../configs/bf-protector_config.toml"

const (
	_allowRequestsCount = 5

	_whiteListIP = "192.0.2.111"
	_blackListIP = "194.0.2.222"
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

var bruteForceTests = []struct {
	name       string
	senderData senderCred
	limits     bruteForceLimits
}{
	{
		name:       "detect brute force on login",
		senderData: getRandomAuthData(),
		limits: bruteForceLimits{
			ip:       _allowRequestsCount + 1,
			login:    _allowRequestsCount,
			password: _allowRequestsCount + 1,
		},
	},
	{
		name:       "detect brute force on password",
		senderData: getRandomAuthData(),
		limits: bruteForceLimits{
			ip:       _allowRequestsCount + 1,
			login:    _allowRequestsCount + 1,
			password: _allowRequestsCount,
		},
	},
	{
		name:       "detect brute force on ip",
		senderData: getRandomAuthData(),
		limits: bruteForceLimits{
			ip:       _allowRequestsCount,
			login:    _allowRequestsCount + 1,
			password: _allowRequestsCount + 1,
		},
	},
}

var blackwhiteIPsTests = []struct {
	name           string
	senderData     senderCred
	limits         bruteForceLimits
	expectedResult bool
	message        string
}{
	{
		name:           "detect IP in white list subnets",
		senderData:     senderCred{util.RandomLogin(), util.RandomPassword(), _whiteListIP},
		limits:         getDefaultRequestLimits(),
		expectedResult: true,
		message:        constant.WhiteListIPText,
	},
	{
		name:           "detect IP in black list subnets",
		senderData:     senderCred{util.RandomLogin(), util.RandomPassword(), _blackListIP},
		limits:         getDefaultRequestLimits(),
		expectedResult: false,
		message:        constant.BlackListIPText,
	},
}

var manageWhiteBlackListTest = []struct {
	name           string
	senderData     senderCred
	limits         bruteForceLimits
	expectedResult bool
	message        string
}{
	{
		name:           "white list add operation/remove operation",
		senderData:     getRandomAuthData(),
		limits:         getDefaultRequestLimits(),
		expectedResult: true,
		message:        constant.WhiteListIPText,
	},
	{
		name:           "black list add operation/remove operation",
		senderData:     getRandomAuthData(),
		limits:         getDefaultRequestLimits(),
		expectedResult: false,
		message:        constant.BlackListIPText,
	},
}

var resetBucketTest = []struct {
	name       string
	senderData senderCred
	limits     bruteForceLimits
}{
	{
		name:       "ip bucket reset",
		senderData: getRandomAuthData(),
		limits: bruteForceLimits{
			ip:       _allowRequestsCount,
			login:    _allowRequestsCount + 1,
			password: _allowRequestsCount + 2,
		},
	},
	{
		name:       "login bucket reset",
		senderData: getRandomAuthData(),
		limits: bruteForceLimits{
			ip:       _allowRequestsCount + 1,
			login:    _allowRequestsCount,
			password: _allowRequestsCount + 2,
		},
	},
}

// TODO add tests for model validation

func TestAuthorization(t *testing.T) {
	config, err := protectorconfig.NewConfig(configFile)
	if err != nil {
		require.NoError(t, err)
	}

	storage := memorystorage.New(config)
	defer storage.Close()

	app := New(config, storage)

	ctx := context.Background()
	err = storage.Seed(ctx,
		[]string{constant.WhiteSubnetsKey, constant.BlackSubnetsKey},
		[][]string{getWhiteListSubnets(), getBlackListSubnets()},
	)
	if err != nil {
		require.NoError(t, err)
	}

	for _, bftest := range bruteForceTests {
		t.Run(bftest.name, func(t *testing.T) {
			resetAppContext(app, storage, bftest.senderData, bftest.limits)
			defer finalizeApp(storage)

			authData := &api.AuthRequest{
				Login:    bftest.senderData.login,
				Password: bftest.senderData.password,
				Ip:       bftest.senderData.ip,
			}
			resp := makeExtraRequestForBruteFroce(t, app, authData, _allowRequestsCount)
			require.Equal(t, false, resp.Success)
			require.Equal(t, constant.LimitExceededText, resp.Msg)
		})
	}

	for _, wbIPstest := range blackwhiteIPsTests {
		t.Run(wbIPstest.name, func(t *testing.T) {
			resetAppContext(app, storage, wbIPstest.senderData, wbIPstest.limits)
			defer finalizeApp(storage)

			authData := &api.AuthRequest{
				Login:    wbIPstest.senderData.login,
				Password: wbIPstest.senderData.password,
				Ip:       wbIPstest.senderData.ip,
			}

			resp := simulateRequestWithContext(t, app.Authorization, authData)
			require.Equal(t, wbIPstest.expectedResult, resp.Success)
			require.Equal(t, wbIPstest.message, resp.Msg)
		})
	}

	for _, wbltest := range manageWhiteBlackListTest {
		t.Run(wbltest.name, func(t *testing.T) {
			resetAppContext(app, storage, wbltest.senderData, wbltest.limits)
			defer finalizeApp(storage)

			authData := &api.AuthRequest{
				Login:    wbltest.senderData.login,
				Password: wbltest.senderData.password,
				Ip:       wbltest.senderData.ip,
			}

			whiteSubnet := wbltest.senderData.ip + "/24"
			err := app.storage.AddToReservedSubnets(ctx, constant.WhiteSubnetsKey, whiteSubnet)
			require.NoError(t, err)

			resp := simulateRequestWithContext(t, app.Authorization, authData)
			require.Equal(t, true, resp.Success)
			require.Equal(t, constant.WhiteListIPText, resp.Msg)

			err = app.storage.RemoveFromReservedSubnets(ctx, constant.WhiteSubnetsKey, whiteSubnet)
			require.NoError(t, err)

			resp = simulateRequestWithContext(t, app.Authorization, authData)
			require.Equal(t, true, resp.Success)
			require.Equal(t, constant.AuthAllowedText, resp.Msg)
		})
	}

	for _, wbltest := range resetBucketTest {
		t.Run(wbltest.name, func(t *testing.T) {
			resetAppContext(app, storage, wbltest.senderData, wbltest.limits)
			defer finalizeApp(storage)

			authData := &api.AuthRequest{
				Login:    wbltest.senderData.login,
				Password: wbltest.senderData.password,
				Ip:       wbltest.senderData.ip,
			}

			resp := makeExtraRequestForBruteFroce(t, app, authData, _allowRequestsCount)
			require.Equal(t, false, resp.Success)
			require.Equal(t, constant.LimitExceededText, resp.Msg)

			resetBucket := &api.ResetBucketRequest{
				Login: authData.Login,
				Ip:    authData.Ip,
			}

			resp, err = app.ResetBuckets(ctx, resetBucket)
			require.NoError(t, err)
			require.Equal(t, true, resp.Success)
			require.Equal(t, constant.BucketResetText, resp.Msg)

			resp = simulateRequestWithContext(t, app.Authorization, authData)
			require.Equal(t, true, resp.Success)
			require.Equal(t, constant.AuthAllowedText, resp.Msg)
		})
	}

	t.Run("simulate and handle error during brute-force", func(t *testing.T) {
		finalizeApp(storage)

		authData := &api.AuthRequest{
			Login:    util.RandomLogin(),
			Password: util.RandomPassword(),
			Ip:       util.RandomIP(),
		}

		memorystorage.RequestContextWG.Add(constant.AttackTypesCount)
		resp, err := app.Authorization(context.Background(), authData)
		memorystorage.RequestContextWG.Wait()

		require.Error(t, err)
		require.Equal(t, false, resp.Success)
		require.Equal(t, "", resp.Msg)
	})
}

func makeExtraRequestForBruteFroce(t *testing.T,
	app *App, authData *api.AuthRequest, requestCount int,
) *api.StatusResponse {
	t.Helper()
	for i := 0; i < requestCount; i++ {
		resp := simulateRequestWithContext(t, app.Authorization, authData)
		require.Equal(t, true, resp.Success)
	}
	return simulateRequestWithContext(t, app.Authorization, authData)
}

func resetAppContext(app *App, storage *memorystorage.MemoryStorage, s senderCred, limits bruteForceLimits) {
	memorystorage.ContextDoneCh = make(chan struct{})

	app.config.AttemptsLimit.IPRequestsMinute = limits.ip
	app.config.AttemptsLimit.LoginRequestsMinute = limits.login
	app.config.AttemptsLimit.PasswordRequestsMinute = limits.password

	storage.AddBruteForceLimit(s.ip, limits.ip)
	storage.AddBruteForceLimit(s.login, limits.login)
	storage.AddBruteForceLimit(s.password, limits.password)
}

func finalizeApp(storage *memorystorage.MemoryStorage) {
	storage.ResetStorage()
	storage.ResetDoneContext()
}

func simulateRequestWithContext(t *testing.T,
	f func(context.Context, *api.AuthRequest) (*api.StatusResponse, error),
	login *api.AuthRequest,
) *api.StatusResponse {
	t.Helper()
	memorystorage.RequestContextWG.Add(constant.AttackTypesCount)
	ctx := context.Background()
	resp, err := f(ctx, login)
	require.NoError(t, err)
	memorystorage.RequestContextWG.Wait()
	return resp
}

func getRandomAuthData() senderCred {
	return senderCred{util.RandomLogin() + "_Login", util.RandomPassword() + "_Password", util.RandomIP()}
}

func getDefaultRequestLimits() bruteForceLimits {
	return bruteForceLimits{_allowRequestsCount, _allowRequestsCount, _allowRequestsCount}
}

// func randWhiteIP() string {
// 	whiteIPs := getWhiteListSubnets()
// 	return whiteIPs[util.RandomIntRange(0, int64(len(whiteIPs)-1))]
// }

// func randBlackIP() string {
// 	blackIPs := getBlackListSubnets()
// 	return blackIPs[util.RandomIntRange(0, int64(len(blackIPs)-1))]
// }

func getWhiteListSubnets() []string {
	return util.ByteRowsToStrings(embed.ReadWhiteList())
}

func getBlackListSubnets() []string {
	return util.ByteRowsToStrings(embed.ReadBlackList())
}

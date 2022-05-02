package protectorapp

// TODO: add test with some shity data and handle errors

import (
	"context"
	"strconv"
	"testing"

	api "github.com/AlexeyInc/Brute-force-protector/api/protoc"
	embed "github.com/AlexeyInc/Brute-force-protector/assets"
	constant "github.com/AlexeyInc/Brute-force-protector/internal/constants"
	memorystorage "github.com/AlexeyInc/Brute-force-protector/internal/storage/memory"
	"github.com/AlexeyInc/Brute-force-protector/util"
	"github.com/stretchr/testify/require"
)

const (
	_allowRequestsCount = 5

	_whiteListIP = "192.0.2.111"
	_blackListIP = "194.0.2.222"
	_maskLen     = 3
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

// TODO add tests for model validation

func TestWhiteBlackList(t *testing.T) {
	var blackwhiteIPsTests = []struct {
		name           string
		senderData     senderCred
		limits         bruteForceLimits
		expectedResult bool
		message        string
	}{
		{
			name:           "detect IP in white list subnets",
			senderData:     senderCred{util.RandomLogin(), util.RandomPassword(), randWhiteIP()},
			limits:         getDefaultRequestLimits(),
			expectedResult: true,
			message:        constant.WhiteListIPText,
		},
		{
			name:           "detect IP in black list subnets",
			senderData:     senderCred{util.RandomLogin(), util.RandomPassword(), randBlackIP()},
			limits:         getDefaultRequestLimits(),
			expectedResult: false,
			message:        constant.BlackListIPText,
		},
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
			responseCheck(t, resp, wbIPstest.expectedResult, wbIPstest.message)
		})
	}

	var manageWhiteBlackListTest = []struct {
		name           string
		listType       string
		senderData     senderCred
		limits         bruteForceLimits
		expectedResult bool
		message        string
	}{
		{
			name:           "white list add operation/remove operation",
			listType:       "white",
			senderData:     getRandomAuthData(),
			limits:         getDefaultRequestLimits(),
			expectedResult: true,
			message:        constant.WhiteListIPText,
		},
		{
			name:           "black list add operation/remove operation",
			listType:       "black",
			senderData:     getRandomAuthData(),
			limits:         getDefaultRequestLimits(),
			expectedResult: false,
			message:        constant.BlackListIPText,
		},
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

			subnet := &api.SubnetRequest{
				Cidr: wbltest.senderData.ip + "/" + randMask(),
			}

			switch wbltest.listType {
			case "white":
				resp, err := app.AddWhiteListIP(testCtx, subnet)
				require.NoError(t, err)
				responseCheck(t, resp, true, constant.WhiteSubnetAddedText)

				resp = simulateRequestWithContext(t, app.Authorization, authData)
				responseCheck(t, resp, true, constant.WhiteListIPText)

				resp, err = app.DeleteWhiteListIP(testCtx, subnet)
				require.NoError(t, err)
				responseCheck(t, resp, true, constant.WhiteSubnetRemovedText)
			case "black":
				resp, err := app.AddBlackListIP(testCtx, subnet)
				require.NoError(t, err)
				responseCheck(t, resp, true, constant.BlackSubnetAddedText)

				resp = simulateRequestWithContext(t, app.Authorization, authData)
				responseCheck(t, resp, false, constant.BlackListIPText)

				resp, err = app.DeleteBlackListIP(testCtx, subnet)
				require.NoError(t, err)
				responseCheck(t, resp, true, constant.BlackSubnetRemovedText)
			}

			resp := simulateRequestWithContext(t, app.Authorization, authData)
			responseCheck(t, resp, true, constant.AuthAllowedText)
		})
	}
}

func TestAuthorization(t *testing.T) {
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
			responseCheck(t, resp, false, constant.LimitExceededText)
		})
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
			responseCheck(t, resp, false, constant.LimitExceededText)

			resetBucket := &api.ResetBucketRequest{
				Login: authData.Login,
				Ip:    authData.Ip,
			}

			resp, err := app.ResetBuckets(testCtx, resetBucket)
			require.NoError(t, err)
			responseCheck(t, resp, true, constant.BucketResetText)

			resp = simulateRequestWithContext(t, app.Authorization, authData)
			responseCheck(t, resp, true, constant.AuthAllowedText)
		})
	}
}

func TestErrHandling(t *testing.T) {
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
		responseCheck(t, resp, false, "")
	})
}

func responseCheck(t *testing.T, resp *api.StatusResponse, expectedResult bool, msg string) {
	require.Equal(t, expectedResult, resp.Success)
	require.Equal(t, msg, resp.Msg)
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

// TODO: добавіть проверку, что ми не можем доабвлять в black list то, что уже есть white list
// check heighlited coverage

func randWhiteIP() string {
	whiteSubnets := getWhiteListSubnets()
	randWhiteSubnet := whiteSubnets[util.RandomIntRange(0, int64(len(whiteSubnets)-1))]
	whiteIP := randWhiteSubnet[:len(randWhiteSubnet)-_maskLen]
	return whiteIP
}

func randBlackIP() string {
	blackSubnets := getBlackListSubnets()
	randBlackSubnet := blackSubnets[util.RandomIntRange(0, int64(len(blackSubnets)-1))]
	blackIP := randBlackSubnet[:len(randBlackSubnet)-_maskLen]
	return blackIP
}

func randMask() string {
	return strconv.Itoa(util.RandomInt(32))
}

func getWhiteListSubnets() []string {
	return util.ByteRowsToStrings(embed.ReadWhiteList())
}

func getBlackListSubnets() []string {
	return util.ByteRowsToStrings(embed.ReadBlackList())
}

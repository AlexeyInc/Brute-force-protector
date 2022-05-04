package protectorapp

import (
	"context"
	"fmt"
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
	_maskLen            = 3

	_netIntersepsExistingBlackSubnet = "0.0.3.0/24"
	_netIntersepsExistingWhiteSubnet = "1.1.2.0/16"
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
	bruteForceTests := []struct {
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
}

func TestBucketReset(t *testing.T) {
	resetBucketTest := []struct {
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

			resp = simulateAuthRequestWithContext(t, app.Authorization, authData, false)
			responseCheck(t, resp, true, constant.AuthAllowedText)
		})
	}
}

func TestWhiteBlackListDetection(t *testing.T) {
	whiteBlackIPsTests := []struct {
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

	for _, wbIPstest := range whiteBlackIPsTests {
		t.Run(wbIPstest.name, func(t *testing.T) {
			resetAppContext(app, storage, wbIPstest.senderData, wbIPstest.limits)
			defer finalizeApp(storage)

			authData := &api.AuthRequest{
				Login:    wbIPstest.senderData.login,
				Password: wbIPstest.senderData.password,
				Ip:       wbIPstest.senderData.ip,
			}

			resp := simulateAuthRequestWithContext(t, app.Authorization, authData, false)
			responseCheck(t, resp, wbIPstest.expectedResult, wbIPstest.message)
		})
	}
}

func TestAddingExistingSubnet(t *testing.T) {
	reserveSubnetsTests := []struct {
		name              string
		subnet            string
		reserveSubnetFunc func(context.Context, *api.SubnetRequest) (*api.StatusResponse, error)
		message           string
	}{
		// dublication test
		{
			name:              "can't add dublication subnet to white list",
			subnet:            getBlackListSubnets()[0],
			reserveSubnetFunc: app.AddBlackListIP,
			message:           constant.ExistInBlackListErr,
		},
		{
			name:              "can't add dublication subnet to black list",
			subnet:            getWhiteListSubnets()[0],
			reserveSubnetFunc: app.AddWhiteListIP,
			message:           constant.ExistInWhiteListErr,
		},
		// intersection test
		{
			name:              "can't add subnet to white list when it has an intersection with existing subnet in black list",
			subnet:            _netIntersepsExistingBlackSubnet,
			reserveSubnetFunc: app.AddWhiteListIP,
			message:           constant.InterceptionBlackListErr,
		},
		{
			name:              "can't add subnet to black list when it has an intersection with existing subnet in white list",
			subnet:            _netIntersepsExistingWhiteSubnet,
			reserveSubnetFunc: app.AddBlackListIP,
			message:           constant.InterceptionWhiteListErr,
		},
	}
	for _, rstest := range reserveSubnetsTests {
		t.Run(rstest.name, func(t *testing.T) {
			defer finalizeApp(storage)

			subnet := &api.SubnetRequest{
				Cidr: rstest.subnet,
			}
			resp, err := rstest.reserveSubnetFunc(context.Background(), subnet)
			require.NoError(t, err)
			responseCheck(t, resp, false, rstest.message)
		})
	}
}

func TestWhiteBlackListManaging(t *testing.T) {
	manageWhiteBlackListTest := []struct {
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

				resp = simulateAuthRequestWithContext(t, app.Authorization, authData, false)
				responseCheck(t, resp, true, constant.WhiteListIPText)

				resp, err = app.DeleteWhiteListIP(testCtx, subnet)
				require.NoError(t, err)
				responseCheck(t, resp, true, constant.WhiteSubnetRemovedText)
				fmt.Println("removed")
			case "black":
				resp, err := app.AddBlackListIP(testCtx, subnet)
				require.NoError(t, err)
				responseCheck(t, resp, true, constant.BlackSubnetAddedText)

				resp = simulateAuthRequestWithContext(t, app.Authorization, authData, false)
				responseCheck(t, resp, false, constant.BlackListIPText)

				resp, err = app.DeleteBlackListIP(testCtx, subnet)
				require.NoError(t, err)
				responseCheck(t, resp, true, constant.BlackSubnetRemovedText)
			}
			fmt.Println("checked")
			resp := simulateAuthRequestWithContext(t, app.Authorization, authData, false)
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

		resp := simulateAuthRequestWithContext(t, app.Authorization, authData, true)
		responseCheck(t, resp, false, "")
	})
}

func TestAuthInvalidInput(t *testing.T) {
	invalidInputTests := []struct {
		name     string
		login    string
		password string
		ip       string
	}{
		{
			name:     "empty login",
			login:    "",
			password: util.RandomPassword(),
			ip:       util.RandomPassword(),
		},
		{
			name:     "empty password",
			login:    util.RandomLogin(),
			password: "",
			ip:       util.RandomPassword(),
		},
		{
			name:     "empty ip",
			login:    util.RandomLogin(),
			password: util.RandomPassword(),
			ip:       "",
		},
	}
	for _, intest := range invalidInputTests {
		t.Run(intest.name, func(t *testing.T) {
			defer finalizeApp(storage)

			auth := &api.AuthRequest{
				Login:    intest.login,
				Password: intest.password,
				Ip:       intest.ip,
			}
			resp, err := app.Authorization(context.Background(), auth)
			require.NoError(t, err)
			responseCheck(t, resp, false, constant.ModelVlidationErr)
		})
	}
}

func TestAuthWithInvalidIPFormat(t *testing.T) {
	defer finalizeApp(storage)

	authData := &api.AuthRequest{
		Login:    util.RandomLogin(),
		Password: util.RandomPassword(),
		Ip:       "invalid IP format",
	}

	resp := simulateAuthRequestWithContext(t, app.Authorization, authData, true)
	require.Equal(t, false, resp.Success)
}

func TestReservationWithInvalidISubnetFormat(t *testing.T) {
	subnet := &api.SubnetRequest{
		Cidr: "invalid subnet format",
	}

	resp, err := app.AddBlackListIP(context.Background(), subnet)
	require.Error(t, err)
	require.Equal(t, false, resp.Success)

	resp, err = app.AddWhiteListIP(context.Background(), subnet)
	require.Error(t, err)
	require.Equal(t, false, resp.Success)
}

func responseCheck(t *testing.T, resp *api.StatusResponse, expectedResult bool, msg string) {
	t.Helper()
	require.Equal(t, expectedResult, resp.Success)
	require.Equal(t, msg, resp.Msg)
}

func makeExtraRequestForBruteFroce(t *testing.T,
	app *App, authData *api.AuthRequest, requestCount int,
) *api.StatusResponse {
	t.Helper()
	for i := 0; i < requestCount; i++ {
		resp := simulateAuthRequestWithContext(t, app.Authorization, authData, false)
		require.Equal(t, true, resp.Success)
	}
	return simulateAuthRequestWithContext(t, app.Authorization, authData, false)
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

func simulateAuthRequestWithContext(t *testing.T,
	f func(context.Context, *api.AuthRequest) (*api.StatusResponse, error),
	login *api.AuthRequest,
	isErrorReqeust bool,
) *api.StatusResponse {
	t.Helper()
	memorystorage.RequestContextWG.Add(constant.AttackTypesCount)
	ctx := context.Background()
	resp, err := f(ctx, login)
	if isErrorReqeust {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
	}
	memorystorage.RequestContextWG.Wait()
	return resp
}

func getRandomAuthData() senderCred {
	return senderCred{util.RandomLogin() + "_Login", util.RandomPassword() + "_Password", util.RandomIP()}
}

func getDefaultRequestLimits() bruteForceLimits {
	return bruteForceLimits{_allowRequestsCount, _allowRequestsCount, _allowRequestsCount}
}

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

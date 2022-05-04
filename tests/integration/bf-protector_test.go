package integration_test

import (
	"context"
	"os"
	"testing"
	"time"

	bfprotector "github.com/AlexeyInc/Brute-force-protector/api/protoc"
	constant "github.com/AlexeyInc/Brute-force-protector/internal/constants"
	redisdb "github.com/AlexeyInc/Brute-force-protector/internal/storage/redis"
	"github.com/AlexeyInc/Brute-force-protector/util"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	N = 10
	M = 100
	K = 1000

	_maxSecToWait int64 = 3
)

type BFProtectorSuite struct {
	suite.Suite
	ctx               context.Context
	serverConn        *grpc.ClientConn
	storage           *redisdb.Storage
	bfprotectorClient bfprotector.BruteForceProtectorServiceClient
	curAuthData       *bfprotector.AuthRequest
}

func (s *BFProtectorSuite) SetupSuite() {
	bfprotectorHostAddr := os.Getenv("BFPROTECTOR_SERVER_ADDR")
	if bfprotectorHostAddr == "" {
		bfprotectorHostAddr = "localhost:8081"
	}

	var err error
	s.serverConn, err = grpc.Dial(bfprotectorHostAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	s.Require().NoError(err)

	s.ctx = context.Background()

	s.bfprotectorClient = bfprotector.NewBruteForceProtectorServiceClient(s.serverConn)

	storageSource := os.Getenv("BFPROTECTOR_STORAGE_SOURCE")
	if storageSource == "" {
		storageSource = "localhost:6379"
	}
	storagePassword := os.Getenv("BFPROTECTOR_STORAGE_PASSWORD")
	if storagePassword == "" {
		storagePassword = "secret123"
	}
	s.storage = &redisdb.Storage{
		Source:   storageSource,
		Password: storagePassword,
	}
	err = s.storage.Connect(s.ctx)
	s.Require().NoError(err)
}

func (s *BFProtectorSuite) TearDownSuite() {
	s.serverConn.Close()
	s.storage.Close()
}

func (s *BFProtectorSuite) TearDownTest() {
	s.resetAuthLimits()
}

func (s *BFProtectorSuite) TestAuthorizationRequest() {
	s.curAuthData = getRandomAuthData()
	s.authorizationCheck(true, constant.AuthAllowedText)
}

func (s *BFProtectorSuite) TestBruteForceAndBucketResetForLogin() {
	s.curAuthData = getRandomAuthData()
	for i := 0; i < N; i++ {
		s.authorizationCheck(true, constant.AuthAllowedText)
	}
	s.authorizationCheck(false, constant.LimitExceededText)

	s.bfprotectorClient.ResetBuckets(s.ctx, &bfprotector.ResetBucketRequest{
		Login: s.curAuthData.Login,
	})
	s.authorizationCheck(true, constant.AuthAllowedText)
}

func (s *BFProtectorSuite) TestBruteForceForPassword() {
	s.curAuthData = getRandomAuthData()
	for i := 0; i < M; i++ {
		s.authorizationCheck(true, constant.AuthAllowedText)
		if (i+1)%N == 0 {
			s.storage.ResetBucket(s.ctx, s.curAuthData.Login)
			s.curAuthData.Login = util.RandomLogin()
		}
	}
	s.authorizationCheck(false, constant.LimitExceededText)
}

func (s *BFProtectorSuite) TestBruteForceAndBuckerResetForIP() {
	s.curAuthData = getRandomAuthData()

	for i := 0; i < K; i++ {
		s.authorizationCheck(true, constant.AuthAllowedText)
		if (i+1)%N == 0 {
			s.storage.ResetBucket(s.ctx, s.curAuthData.Login)
			s.curAuthData.Login = util.RandomLogin()
		}
		if (i+1)%M == 0 {
			s.storage.ResetBucket(s.ctx, s.curAuthData.Password)
			s.curAuthData.Password = util.RandomPassword()
		}
	}
	s.authorizationCheck(false, constant.LimitExceededText)

	s.bfprotectorClient.ResetBuckets(s.ctx, &bfprotector.ResetBucketRequest{
		Ip: s.curAuthData.Ip,
	})
	s.authorizationCheck(true, constant.AuthAllowedText)
}

func (s *BFProtectorSuite) TestBruteForceWithRandTimeIntervals() {
	s.curAuthData = getRandomAuthData()
	for i := 0; i < N; i++ {
		s.bfprotectorClient.Authorization(s.ctx, s.curAuthData)

		time.Sleep(time.Duration(util.RandomInt(_maxSecToWait)) * time.Second)
	}
	s.authorizationCheck(false, constant.LimitExceededText)
}

func (s *BFProtectorSuite) TestBlackWhiteSubnetsManagement() {
	reserveSubnet := util.RandomSubnet()
	subnetRequest := &bfprotector.SubnetRequest{
		Cidr: reserveSubnet,
	}
	s.curAuthData = &bfprotector.AuthRequest{
		Login:    util.RandomLogin(),
		Password: util.RandomPassword(),
		Ip:       reserveSubnet[:len(reserveSubnet)-3],
	}

	// white subnet tests
	resp, err := s.bfprotectorClient.AddWhiteListIP(s.ctx, subnetRequest)
	s.Require().NoError(err)
	s.responseCheck(resp, true, constant.WhiteSubnetAddedText)
	s.authorizationCheck(true, constant.WhiteListIPText)

	resp, err = s.bfprotectorClient.DeleteWhiteListIP(s.ctx, subnetRequest)
	s.Require().NoError(err)
	s.responseCheck(resp, true, constant.WhiteSubnetRemovedText)
	s.authorizationCheck(true, constant.AuthAllowedText)

	// black subnet tests
	resp, err = s.bfprotectorClient.AddBlackListIP(s.ctx, subnetRequest)
	s.Require().NoError(err)
	s.responseCheck(resp, true, constant.BlackSubnetAddedText)
	s.authorizationCheck(false, constant.BlackListIPText)

	resp, err = s.bfprotectorClient.DeleteBlackListIP(s.ctx, subnetRequest)
	s.Require().NoError(err)
	s.responseCheck(resp, true, constant.BlackSubnetRemovedText)
	s.authorizationCheck(true, constant.AuthAllowedText)
}

func (s *BFProtectorSuite) authorizationCheck(excpectedResult bool, msg string) {
	resp, err := s.bfprotectorClient.Authorization(s.ctx, s.curAuthData)
	s.Require().NoError(err)
	s.Require().Equal(excpectedResult, resp.Success)
	s.Require().Equal(msg, resp.Msg)
}

func (s *BFProtectorSuite) responseCheck(resp *bfprotector.StatusResponse, excpectedResult bool, msg string) { //nolint
	s.Require().Equal(excpectedResult, resp.Success)
	s.Require().Equal(msg, resp.Msg)
}

func TestBFProtectorSuite(t *testing.T) {
	suite.Run(t, new(BFProtectorSuite))
}

func getRandomAuthData() *bfprotector.AuthRequest {
	return &bfprotector.AuthRequest{
		Login:    util.RandomLogin(),
		Password: util.RandomPassword(),
		Ip:       util.RandomIP(),
	}
}

func (s *BFProtectorSuite) resetAuthLimits() {
	s.storage.ResetBucket(s.ctx, s.curAuthData.Ip)
	s.storage.ResetBucket(s.ctx, s.curAuthData.Login)
	s.storage.ResetBucket(s.ctx, s.curAuthData.Password)
}

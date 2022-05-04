package constant

const (
	AttackTypesCount = 3

	WhiteSubnetsKey = "whiteListSubnets"
	BlackSubnetsKey = "blackListSubnets"

	WhiteSubnetAddedText   = "subnet added to white list"
	WhiteSubnetRemovedText = "subnet removed from white list"
	BlackSubnetAddedText   = "subnet added to black list"
	BlackSubnetRemovedText = "subnet removed from black list"
	BucketResetText        = "bucket(s) successfully reset"
	WhiteListIPText        = "sender ip is in whitelist"
	BlackListIPText        = "sender ip is in black list"
	AuthAllowedText        = "authorization allowed"
	LimitExceededText      = "limit of authorization attempts exceeded"

	ReadPeerFromCtxErr       = "can't read peer info from context"
	BruteForceCheckErr       = "error during brute force check"
	ResetBucketErr           = "failed to reset bucket"
	ModelVlidationErr        = "fields in request model can't be empty"
	WhiteListAddErr          = "failed to add subnet to white list"
	BlackListAddErr          = "failed to add subnet to black list"
	ExistInWhiteListErr      = "already exist in white list"
	ExistInBlackListErr      = "already exist in black list"
	InterceptionWhiteListErr = "subnet intercepts subnet from white list"
	InterceptionBlackListErr = "subnet intercepts subnet from black list"
	WhiteListRemoveErr       = "failed to remove subnet from white list"
	BlackListRemoveErr       = "failed to remove subnet from black list"
	CreateClientErr          = "can't create client"
	ReadConfigErr            = "can't read config file"
	DBConnectionErr          = "connection to database failed"
	BfProtectorReqErr        = "failed to make request to brute-force-protector service"
	SubnetParseErr           = "failed to parse subnet (cidr)"
	InvalidIPErr             = "invalid format of ip address"

	DatabaseSeedErr    = "can't seed database"
	DBRequestErr       = "failed to make db request"
	DBSubnetsErr       = "failed to get reserved subnets from db"
	DBRemoveSubnetErr  = "failed to remove subnet from db"
	DBReserveSubnetErr = "failed to reserve subnet"
)

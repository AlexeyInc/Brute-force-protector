package constant

const (
	AttackTypesCount = 3

	WhiteIPsKey = "whiteListIPs"
	BlackIPsKey = "blackListIPs"

	WhiteIpAddedText   = "ip added to white list"
	WhiteIpRemovedText = "ip removed from white list"
	BlackIpAddedText   = "ip added to black list"
	BlackIpRemovedText = "ip removed from black list"
	BucketResetText    = "bucket(s) successfully reset"
	WhiteListIpText    = "sender ip is in whitelist"
	BlackListIpText    = "sender ip is in black list"
	AuthAllowedText    = "authorization allowed"
	LimitExceededText  = "limit of authorization attempts exceeded"

	ReadPeerFromCtxErr = "can't read peer info from context"
	BruteForceCheckErr = "error during brute force check"
	ResetBucketErr     = "failed to reset bucket"
	ModelVlidationErr  = "fields in request model can't be empty"
	WhiteListAddErr    = "failed to add ip to white list"
	BlackListAddErr    = "failed to add ip to black list"
	WhiteListRemoveErr = "failed to remove ip from white list"
	BlackListRemoveErr = "failed to remove ip from black list"
	CreateClientErr    = "can't create client"
	ReadConfigErr      = "can't read config file"
	DbConnectionErr    = "connection to database failed"
	DatabaseSeedErr    = "can't seed database"
	BfProtectorReqErr  = "failed to make request to brute-force-protector service"
)

package constant

const (
	AttackTypesCount = 3

	WhiteIPsKey = "whiteListIPs"
	BlackIPsKey = "blackListIPs"

	WhiteIPAddedText   = "ip added to white list"
	WhiteIPRemovedText = "ip removed from white list"
	BlackIPAddedText   = "ip added to black list"
	BlackIPRemovedText = "ip removed from black list"
	BucketResetText    = "bucket(s) successfully reset"
	WhiteListIPText    = "sender ip is in whitelist"
	BlackListIPText    = "sender ip is in black list"
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
	DBConnectionErr    = "connection to database failed"
	DatabaseSeedErr    = "can't seed database"
	BfProtectorReqErr  = "failed to make request to brute-force-protector service"
)

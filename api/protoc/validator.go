package brute_force_protector

func (model *AuthRequest) IsValid() bool {
	if model.GetIp() == "" {
		return false
	}
	if model.GetLogin() == "" {
		return false
	}
	if model.GetPassword() == "" {
		return false
	}
	return true
}

func (model *ResetBucketRequest) IsValid() bool {
	return model.GetIp() == "" &&
		model.GetLogin() == ""
}

func (model *SubnetRequest) IsValid() bool {
	return model.GetIp() == ""
}

package iamrole

func in(list []string, val string) bool {
	for _, l := range list {
		if l == val {
			return true
		}
	}
	return false
}

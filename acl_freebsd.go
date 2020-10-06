// Copyright (c) 2015 Joseph Naegele. See LICENSE file.

package acl

import "errors"

func (acl *ACL) addBaseEntries(path string) error {
	return nil
}

// GetFileExtended returns the extended access ACL associated with the given file path.
func GetFileExtended(path string) (*ACL, error) {
	return nil, errors.New("GetFileExtended only supported on Darwin")
}

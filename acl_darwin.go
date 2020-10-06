// Copyright (c) 2015 Joseph Naegele. See LICENSE file.

package acl

// #include <sys/acl.h>
// #include <sys/types.h>
import "C"
import (
	"os"
	"strings"
)

const (
	TagExtendedAllow Tag = C.ACL_EXTENDED_ALLOW
	TagExtendedDeny  Tag = C.ACL_EXTENDED_DENY

	PermRead               Perm = C.ACL_READ_DATA
	PermListDirectory           = PermRead
	PermWrite              Perm = C.ACL_WRITE_DATA
	PermAddFile                 = PermWrite
	PermSearch                  = PermExecute
	PermDelete             Perm = C.ACL_DELETE
	PermAppend             Perm = C.ACL_APPEND_DATA
	PermAddSubdirectory         = PermAppend
	PermDeleteChild        Perm = C.ACL_DELETE_CHILD
	PermReadAttributes     Perm = C.ACL_READ_ATTRIBUTES
	PermWriteAttributes    Perm = C.ACL_WRITE_ATTRIBUTES
	PermReadExtAttributes  Perm = C.ACL_READ_EXTATTRIBUTES
	PermWriteExtAttributes Perm = C.ACL_WRITE_EXTATTRIBUTES
	PermReadSecurity       Perm = C.ACL_READ_SECURITY
	PermWriteSecurity      Perm = C.ACL_WRITE_SECURITY
	PermChangeOwner        Perm = C.ACL_CHANGE_OWNER
	PermSynchronize        Perm = C.ACL_SYNCHRONIZE
)

func (p Perm) String() string {
	switch p {
	case PermRead:
		return "Read"
	case PermWrite:
		return "Write"
	case PermExecute:
		return "Execute"
	case PermDelete:
		return "Delete"
	case PermAppend:
		return "Append"
	case PermDeleteChild:
		return "DeleteChild"
	case PermReadAttributes:
		return "ReadAttributes"
	case PermWriteAttributes:
		return "WriteAttributes"
	case PermReadExtAttributes:
		return "ReadExtAttributes"
	case PermWriteExtAttributes:
		return "WriteExtAttributes"
	case PermReadSecurity:
		return "ReadSecurity"
	case PermWriteSecurity:
		return "WriteSecurity"
	case PermChangeOwner:
		return "ChangeOwner"
	case PermSynchronize:
		return "Synchronize"
	}
	return "<unknown Perm>"
}

var allPerms = []Perm{
	PermRead,
	PermWrite,
	PermExecute,
	PermDelete,
	PermAppend,
	PermDeleteChild,
	PermReadAttributes,
	PermWriteAttributes,
	PermReadExtAttributes,
	PermWriteExtAttributes,
	PermReadSecurity,
	PermWriteSecurity,
	PermChangeOwner,
	PermSynchronize,
}

func (acl *ACL) addBaseEntries(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	mode := fi.Mode().Perm()
	var r, w, e bool

	r = mode&userRead == userRead
	w = mode&userWrite == userWrite
	e = mode&userExec == userExec
	if err := acl.addBaseEntryFromMode(TagExtendedAllow, r, w, e); err != nil {
		return err
	}

	return nil
}

func (acl *ACL) addBaseEntryFromMode(tag Tag, read, write, execute bool) error {
	e, err := acl.CreateEntry()
	if err != nil {
		return err
	}
	if err = e.SetTag(tag); err != nil {
		return err
	}
	p, err := e.GetPermset()
	if err != nil {
		return err
	}
	if err := p.addPermsFromMode(read, write, execute); err != nil {
		return err
	}
	return nil
}

func (p *Permset) addPermsFromMode(read, write, execute bool) error {
	if read {
		if err := p.AddPerm(PermRead); err != nil {
			return err
		}
	}
	if write {
		if err := p.AddPerm(PermWrite); err != nil {
			return err
		}
	}
	if execute {
		if err := p.AddPerm(PermExecute); err != nil {
			return err
		}
	}
	return nil
}

func (pset *Permset) String() string {
	var all []string
	for _, perm := range allPerms {
		rv, _ := C.acl_get_perm_np(pset.p, C.acl_perm_t(perm))
		if rv > 0 {
			all = append(all, perm.String())
		}
	}
	return strings.Join(all, ", ")
}

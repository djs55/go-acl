// Copyright (c) 2015 Joseph Naegele. See LICENSE file.

package acl

// #ifdef __APPLE__
//  #include <sys/types.h>
// #endif
// #include <membership.h>
// #include <string.h>
// #include <sys/acl.h>
// #cgo linux LDFLAGS: -lacl
import "C"
import (
	"fmt"
	"unsafe"

	"github.com/pkg/errors"
)

const (
	TagUndefined Tag = C.ACL_UNDEFINED_TAG
)

// Entry is an entry in an ACL.
type Entry struct {
	e C.acl_entry_t
}

// SetPermset sets the permissions for an ACL Entry.
func (entry *Entry) SetPermset(pset *Permset) error {
	rv, err := C.acl_set_permset(entry.e, pset.p)
	if rv < 0 {
		return errors.Wrap(err, "acl_set_permset")
	}
	return nil
}

// Copy copies an Entry.
func (entry *Entry) Copy() (*Entry, error) {
	var cdst C.acl_entry_t
	rv, err := C.acl_copy_entry(cdst, entry.e)
	if rv < 0 {
		return nil, errors.Wrap(err, "acl_copy_entry")
	}
	return &Entry{cdst}, nil
}

// SetQualifier sets the Uid or Gid the entry applies to.
func (entry *Entry) SetQualifier(id int) error {
	var uuid C.uuid_t
	result := C.mbr_uid_to_uuid(C.uint(id), &uuid[0])
	if result != 0 {
		message := C.strerror(result)
		return fmt.Errorf("mbr_uid_to_uuid: %s", C.GoString(message))
	}
	rv, err := C.acl_set_qualifier(entry.e, unsafe.Pointer(&uuid[0]))
	if rv < 0 {
		return errors.Wrapf(err, "acl_set_qualifier(%d)", id)
	}
	return nil
}

// GetQualifier returns the Uid or Gid the entry applies to.
func (entry *Entry) GetQualifier() (int, error) {
	q := C.acl_get_qualifier(entry.e)
	if q == nil {
		return -1, fmt.Errorf("unable to get qualifier")
	}
	// q is a *guid_t
	defer func() {
		C.acl_free(q)
	}()
	uuid := (*C.uchar)(q)
	var id C.id_t
	var ty C.int
	result := C.mbr_uuid_to_id(uuid, &id, &ty)
	if result != 0 {
		message := C.strerror(result)
		return -1, fmt.Errorf("mbr_uuid_to_id: %s", C.GoString(message))
	}
	if ty == C.ID_TYPE_GID {
		return -1, nil
	}
	return int(id), nil
}

// GetPermset returns the permission for an Entry.
func (entry *Entry) GetPermset() (*Permset, error) {
	var ps C.acl_permset_t
	rv, err := C.acl_get_permset(entry.e, &ps)
	if rv < 0 {
		return nil, errors.Wrap(err, "acl_get_permset")
	}
	return &Permset{ps}, nil
}

// GetTag returns the Tag for an Entry.
func (entry *Entry) GetTag() (Tag, error) {
	var t C.acl_tag_t
	rv, err := C.acl_get_tag_type(entry.e, &t)
	if rv < 0 {
		return TagUndefined, errors.Wrap(err, "acl_get_tag_type")
	}
	return Tag(t), nil
}

// SetTag sets the Tag for an Entry.
func (entry *Entry) SetTag(t Tag) error {
	rv, err := C.acl_set_tag_type(entry.e, C.acl_tag_t(t))
	if rv < 0 {
		return errors.Wrap(err, "acl_set_tag_type")
	}
	return nil
}

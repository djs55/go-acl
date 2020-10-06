package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/naegelejd/go-acl"
	"github.com/pkg/errors"
)

func main() {
	flag.Parse()
	if flag.NArg() < 1 {
		log.Fatal("Missing filename")
	}
	filename := flag.Arg(0)

	txt, err := printACL(filename)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Before: %s\n", txt)

	err = modifyOrAdd(filename, 501)
	if err != nil {
		log.Fatal(err)
	}
	txt, err = printACL(filename)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("After: %s\n", txt)
}

func printACL(filename string) (string, error) {
	a, err := acl.GetFileExtended(filename)
	if os.IsNotExist(err) {
		return "<none>", nil
	}
	if err != nil {
		return "", errors.Wrap(err, "getting extended ACL from "+filename)
	}
	defer a.Free()

	return a.String(), nil
}

func modifyOrAdd(filename string, uid int) error {
	a, err := acl.GetFileExtended(filename)
	if os.IsNotExist(err) {
		return errors.Wrap(addNewEntry(filename, acl.New(), uid), "adding new entry for "+filename)
	}
	if err != nil {
		return errors.Wrap(err, "getting extended ACL from "+filename)
	}
	defer a.Free()
	done, err := modifyExistingEntry(filename, a, uid)
	if err != nil {
		return errors.Wrap(err, "modifying existing entry for "+filename)
	}
	if done {
		return nil
	}
	return errors.Wrap(addNewEntry(filename, a, uid), "adding new entry for "+filename)
}

func modifyExistingEntry(filename string, a *acl.ACL, uid int) (bool, error) {
	for entry := a.FirstEntry(); entry != nil; entry = a.NextEntry() {
		tag, err := entry.GetTag()
		if err != nil {
			return false, errors.Wrapf(err, "getting tag in ACL entry %v for %s", entry, filename)
		}
		if tag != acl.TagExtendedAllow {
			continue
		}
		q, err := entry.GetQualifier()
		if err != nil {
			return false, errors.Wrapf(err, "getting qualifier in ACL entry %v for %s", entry, filename)
		}
		if q != uid {
			continue
		}
		permset, err := entry.GetPermset()
		if err != nil {
			return false, errors.Wrapf(err, "getting permission set of entry %v for %s", entry, filename)
		}
		if err := permset.AddPerm(acl.PermReadExtAttributes); err != nil {
			return false, errors.Wrapf(err, "adding PermReadExtAttributes to entry %v for %s", entry, filename)
		}
		if err := permset.AddPerm(acl.PermWriteExtAttributes); err != nil {
			return false, errors.Wrapf(err, "adding PermWriteExtAttributes to entry %v for %s", entry, filename)
		}
		if err := entry.SetPermset(permset); err != nil {
			return false, errors.Wrapf(err, "setting permission set on entry %v for %s", entry, filename)
		}
		if err := a.SetFileExtended(filename); err != nil {
			return false, errors.Wrapf(err, "setting extended ACLs on %s", filename)
		}
		return true, nil
	}
	return false, nil
}

func addNewEntry(filename string, a *acl.ACL, uid int) error {

	entry, err := a.CreateEntry()
	if err != nil {
		return errors.Wrap(err, "creating entry in ACL for "+filename)
	}
	if err := entry.SetTag(acl.TagExtendedAllow); err != nil {
		return errors.Wrap(err, "setting ACL tag")
	}
	fmt.Printf("entry = %v\n", entry)
	if err := entry.SetQualifier(uid); err != nil {
		return errors.Wrap(err, "setting qualifier in ACL for "+filename)
	}
	permset, err := entry.GetPermset()
	if err != nil {
		return errors.Wrapf(err, "getting permission set of entry %v for %s", entry, filename)
	}
	if err := permset.AddPerm(acl.PermReadExtAttributes); err != nil {
		return errors.Wrapf(err, "adding PermReadExtAttributes to entry %v for %s", entry, filename)
	}
	if err := permset.AddPerm(acl.PermWriteExtAttributes); err != nil {
		return errors.Wrapf(err, "adding PermWriteExtAttributes to entry %v for %s", entry, filename)
	}
	if err := entry.SetPermset(permset); err != nil {
		return errors.Wrapf(err, "setting permission set on entry %v for %s", entry, filename)
	}
	if err := a.SetFileExtended(filename); err != nil {
		return errors.Wrapf(err, "setting extended ACLs on %s", filename)
	}
	return nil
}

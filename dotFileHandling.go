package webserver

import (
	"net/http"
	"os"
	"strings"

	"gitmaster.hq.aland-mariwan.de/go/logger.git"
)

func containsDotFile(name string) bool {
	parts := strings.Split(name, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, ".") {
			return true
		}
	}
	return false
}

type dotFileHidingFile struct {
	http.File
}

type dotFileHidingFileSystem struct {
	http.FileSystem
}

func (fs dotFileHidingFileSystem) Open(name string) (http.File, error) {
	if containsDotFile(name) { // If dot file, return 403 response
		return nil, os.ErrPermission
	}

	logger.Info("open: " + name)

	file, err := fs.FileSystem.Open(name)
	if err != nil {
		return nil, err
	}
	return dotFileHidingFile{file}, err
}

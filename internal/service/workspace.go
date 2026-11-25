package service

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

type Workspace struct {
	ID   string `json:"workspace_id"`
	Path string `json:"-"`
}

func normalizeWorkspaces(in []Workspace) (map[string]Workspace, error) {
	out := make(map[string]Workspace, len(in))
	for _, w := range in {
		if !identifier.MatchString(w.ID) {
			return nil, fmt.Errorf("invalid workspace ID %q", w.ID)
		}
		if _, ok := out[w.ID]; ok {
			return nil, fmt.Errorf("duplicate workspace %q", w.ID)
		}
		abs, err := filepath.Abs(w.Path)
		if err != nil {
			return nil, err
		}
		w.Path, err = filepath.EvalSymlinks(abs)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(w.Path)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("workspace %q is not a directory", w.ID)
		}
		out[w.ID] = w
	}
	return out, nil
}

func (s *Service) workspace(id string) (Workspace, error) {
	w, ok := s.workspaces[id]
	if !ok {
		return w, fault("not_found", "workspace does not exist")
	}
	return w, nil
}

func relative(path string) (string, error) {
	if path == "" {
		path = "."
	}
	if path != "." && (!filepath.IsLocal(path) || filepath.Clean(path) != path) {
		return "", fault("invalid_argument", "path must be relative to the workspace")
	}
	return path, nil
}

func (w Workspace) directory(path string) (string, string, error) {
	path, err := relative(path)
	if err != nil {
		return "", "", err
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(w.Path, path))
	if err != nil {
		return "", "", fault("not_found", "directory does not exist")
	}
	rel, err := filepath.Rel(w.Path, resolved)
	if err != nil || !filepath.IsLocal(rel) {
		return "", "", fault("invalid_argument", "directory escapes workspace")
	}
	root, err := os.OpenRoot(w.Path)
	if err != nil {
		return "", "", err
	}
	defer root.Close()
	info, err := root.Stat(rel)
	if err != nil || !info.IsDir() {
		return "", "", fault("not_found", "directory does not exist")
	}
	return resolved, rel, nil
}

func (s *Service) browse(c command) (any, error) {
	w, err := s.workspace(c.Workspace)
	if err != nil {
		return nil, err
	}
	_, rel, err := w.directory(c.Path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(w.Path)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	dir, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() && entry.Name() > c.NameAfter {
			names = append(names, entry.Name())
		}
	}
	slices.Sort(names)
	names = append([]string{}, names...)
	more := len(names) > 100
	if more {
		names = names[:100]
	}
	var parent any
	if rel != "." {
		parent = filepath.Dir(rel)
	}
	return map[string]any{"path": rel, "parent": parent, "directories": names, "more": more}, nil
}

// File links resolve relative to the conversation by default. The file browser
// can choose a workspace explicitly, and absolute links can select any configured root.
func (s *Service) fileLocation(c command) (Workspace, string, error) {
	if !filepath.IsAbs(c.Path) && c.Workspace != "" {
		w, err := s.workspace(c.Workspace)
		if err != nil {
			return Workspace{}, "", err
		}
		path, err := relative(c.Path)
		return w, path, err
	}
	if !filepath.IsAbs(c.Path) {
		t, err := s.store.thread(s.ctx, c.Thread)
		if err != nil {
			return Workspace{}, "", err
		}
		w, err := s.workspace(t.Workspace)
		if err != nil {
			return Workspace{}, "", err
		}
		if path, err := relative(c.Path); err == nil {
			return w, filepath.Join(t.Path, path), nil
		}
		c.Path = filepath.Join(w.Path, t.Path, c.Path)
	}
	var best Workspace
	var path string
	for _, w := range s.workspaces {
		rel, err := filepath.Rel(w.Path, c.Path)
		if err == nil && filepath.IsLocal(rel) && (len(w.Path) > len(best.Path) || (w.Path == best.Path && w.ID < best.ID)) {
			best, path = w, rel
		}
	}
	if best.ID == "" {
		return Workspace{}, "", fault("not_found", "file is outside the configured workspaces")
	}
	return best, path, nil
}

func (s *Service) openProjectFile(c command) (*os.File, os.FileInfo, error) {
	w, path, err := s.fileLocation(c)
	if err != nil {
		return nil, nil, err
	}
	if path == "." || c.Offset < 0 {
		return nil, nil, fault("invalid_argument", "a file path and nonnegative offset are required")
	}
	project, err := os.OpenRoot(w.Path)
	if err != nil {
		return nil, nil, err
	}
	defer project.Close()
	target, err := project.Lstat(path)
	if err != nil || !target.Mode().IsRegular() {
		return nil, nil, fault("not_found", "regular file does not exist")
	}
	f, err := project.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, fault("not_found", "file is unavailable")
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, nil, fault("not_found", "regular file is unavailable")
	}
	return f, info, nil
}

func (s *Service) readFile(c command) (any, error) {
	f, info, err := s.openProjectFile(c)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if c.Offset > info.Size() {
		return nil, fault("invalid_argument", "offset exceeds file size")
	}
	version := fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano())
	if c.Offset > 0 && c.Version != version {
		return nil, fault("file_changed", "restart the read from offset zero")
	}
	pageSize := 48 << 10
	if c.Limit > 0 {
		// Leave room for Base64, JSON and MQTT framing in a 256 KiB packet.
		pageSize = min(c.Limit, 168<<10)
	}
	buf := make([]byte, min(int64(pageSize), info.Size()-c.Offset))
	n, err := f.ReadAt(buf, c.Offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return nil, fault("file_changed", "restart the read from offset zero")
	}
	return map[string]any{"bytes": base64.StdEncoding.EncodeToString(buf[:n]), "version": version, "next_offset": c.Offset + int64(n), "more": c.Offset+int64(n) < info.Size()}, nil
}

func (s *Service) matchWorkspace(path string) (Workspace, string, bool) {
	var best Workspace
	var relativePath string
	path, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(path) {
		return best, "", false
	}
	for _, w := range s.workspaces {
		rel, err := filepath.Rel(w.Path, path)
		if err == nil && filepath.IsLocal(rel) && (len(w.Path) > len(best.Path) || (w.Path == best.Path && strings.Compare(w.ID, best.ID) < 0)) {
			best, relativePath = w, rel
		}
	}
	return best, relativePath, best.ID != ""
}

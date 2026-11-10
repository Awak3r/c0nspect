package conspectclient

import (
	"bytes"
	"context"
	"errors"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"io/fs"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	_ "golang.org/x/image/webp"
)

func openFilesRoot(name string) (*os.Root, error) {
	name = filepath.Clean(name)
	invalid := errors.New("CONSPECT_FILES_ROOT must be a readable directory, not a symlink")
	before, err := os.Lstat(name)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, invalid
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		return nil, invalid
	}
	info, err := root.Stat(".")
	if err != nil || !os.SameFile(before, info) {
		root.Close()
		return nil, invalid
	}
	return root, nil
}

// ReadMarkdown reads only a relative .md file beneath the configured FilesRoot.
func (c *Client) ReadMarkdown(relativePath string) (string, error) {
	return c.readText(relativePath, false)
}

// ReadSource additionally permits .txt files; it never fetches a URL.
func (c *Client) ReadSource(relativePath string) (string, error) {
	return c.readText(relativePath, true)
}

func (c *Client) readText(relativePath string, allowTXT bool) (string, error) {
	ext := strings.ToLower(path.Ext(relativePath))
	if ext != ".md" && !(allowTXT && ext == ".txt") {
		return "", errors.New("source file must have an allowed .md or .txt extension (.md only for ReadMarkdown)")
	}
	data, err := c.readLocal(relativePath, maxMarkdownBytes)
	if err != nil {
		return "", err
	}
	text := string(data)
	if err := validateText(text); err != nil {
		return "", err
	}
	return text, nil
}

func validateText(text string) error {
	if len(text) > maxMarkdownBytes {
		return errors.New("Markdown or source text exceeds the 2 MiB limit")
	}
	if !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
		return errors.New("Markdown or source text must be UTF-8 without NUL bytes")
	}
	return nil
}

func validRelativePath(name string) bool {
	if len(name) == 0 || name == "." || len(name) > 4096 || !utf8.ValidString(name) || !fs.ValidPath(name) ||
		!filepath.IsLocal(name) || filepath.IsAbs(name) || strings.ContainsAny(name, "\\:") {
		return false
	}
	for _, c := range name {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func (c *Client) readLocal(name string, maxBytes int64) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return nil, errors.New("Conspect client is closed")
	}
	if c.root == nil {
		return nil, errors.New("local file tools are disabled; configure CONSPECT_FILES_ROOT at startup to enable them")
	}
	if !validRelativePath(name) {
		return nil, errors.New("file path must be relative to CONSPECT_FILES_ROOT without traversal, backslashes, drive prefixes or control characters")
	}
	invalid := errors.New("cannot read local file: every path component must be accessible without symlinks and the target must be a regular file")
	current := c.root
	var owned *os.Root
	defer func() {
		if owned != nil {
			owned.Close()
		}
	}()
	parts := strings.Split(name, "/")
	// Pin each directory independently. Root remains the escape-resistant
	// boundary even if a directory is renamed during the operation.
	for _, part := range parts[:len(parts)-1] {
		before, err := current.Lstat(part)
		if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			return nil, invalid
		}
		next, err := current.OpenRoot(part)
		if err != nil {
			return nil, invalid
		}
		info, statErr := next.Stat(".")
		after, linkErr := current.Lstat(part)
		if statErr != nil || linkErr != nil || !os.SameFile(before, info) || !os.SameFile(after, info) || after.Mode()&os.ModeSymlink != 0 {
			next.Close()
			return nil, invalid
		}
		if owned != nil {
			owned.Close()
		}
		owned = next
		current = next
	}
	base := parts[len(parts)-1]
	before, err := current.Lstat(base)
	if err != nil || !before.Mode().IsRegular() {
		return nil, invalid
	}
	if before.Size() > maxBytes {
		return nil, errors.New("local file exceeds the allowed size limit")
	}
	f, err := current.OpenFile(base, readOnlyFlags(), 0)
	if err != nil {
		return nil, invalid
	}
	defer f.Close()
	info, statErr := f.Stat()
	after, linkErr := current.Lstat(base)
	if statErr != nil || linkErr != nil || !info.Mode().IsRegular() || !after.Mode().IsRegular() ||
		!os.SameFile(before, info) || !os.SameFile(after, info) {
		return nil, invalid
	}
	if info.Size() > maxBytes {
		return nil, errors.New("local file exceeds the allowed size limit")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, errors.New("could not read the local file")
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("local file exceeds the allowed size limit")
	}
	return data, nil
}

// UploadImage uploads one bounded local image. It returns the API's inert
// Markdown fragment; it never appends it to the note or changes its text version.
func (c *Client) UploadImage(ctx context.Context, noteID, relativePath string) (UploadedImage, error) {
	if !validID(noteID) {
		return UploadedImage{}, errors.New("note ID must be 32 lowercase hexadecimal characters")
	}
	if ctx == nil {
		return UploadedImage{}, errors.New("a request context is required")
	}
	if err := ctx.Err(); err != nil {
		return UploadedImage{}, err
	}
	ext := strings.ToLower(path.Ext(relativePath))
	mimeByExtension := map[string]string{".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp"}
	expectedMIME, ok := mimeByExtension[ext]
	if !ok {
		return UploadedImage{}, errors.New("image file must have a .png, .jpg, .jpeg or .webp extension")
	}
	data, err := c.readLocal(relativePath, maxImageBytes)
	if err != nil {
		return UploadedImage{}, err
	}
	actualMIME := http.DetectContentType(data)
	if actualMIME != expectedMIME {
		return UploadedImage{}, errors.New("image contents must be PNG, JPEG or WebP and match the filename extension")
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || (format != "png" && format != "jpeg" && format != "webp") {
		return UploadedImage{}, errors.New("could not decode the image header")
	}
	if config.Width <= 0 || config.Height <= 0 || config.Width > 16000 || config.Height > 16000 || int64(config.Width)*int64(config.Height) > 20000000 {
		return UploadedImage{}, errors.New("image must have positive dimensions, at most 20 million pixels and at most 16000 pixels per side")
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	headers := make(textproto.MIMEHeader)
	headers.Set("Content-Disposition", mime.FormatMediaType("form-data", map[string]string{"name": "file", "filename": path.Base(relativePath)}))
	headers.Set("Content-Type", actualMIME)
	part, err := writer.CreatePart(headers)
	if err != nil {
		return UploadedImage{}, errors.New("could not construct the image upload")
	}
	if _, err := part.Write(data); err != nil {
		return UploadedImage{}, errors.New("could not construct the image upload")
	}
	if err := writer.Close(); err != nil {
		return UploadedImage{}, errors.New("could not construct the image upload")
	}
	var result UploadedImage
	if _, err := c.request(ctx, http.MethodPost, "/notes/"+noteID+"/attachments", nil, body.Bytes(), writer.FormDataContentType(), "", http.StatusCreated, &result); err != nil {
		return UploadedImage{}, err
	}
	if !validID(result.Attachment.ID) || result.Attachment.NoteID != noteID || result.Attachment.MIME != actualMIME ||
		result.Attachment.Size != int64(len(data)) || result.Markdown == "" {
		return UploadedImage{}, uncertainWrite(http.MethodPost, errors.New("Conspect API returned invalid uploaded image metadata"))
	}
	return result, nil
}

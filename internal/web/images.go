package web

import (
	"bytes"
	"errors"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"conspect/internal/store"

	_ "golang.org/x/image/webp"
)

func cleanFilename(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, name)
	if name == "." || name == "/" || !utf8.ValidString(name) || name == "" {
		return "image"
	}
	if len(name) > 200 {
		for len(name) > 200 {
			_, n := utf8.DecodeLastRuneInString(name)
			name = name[:len(name)-n]
		}
	}
	return name
}
func imageMarkdown(a store.Attachment) string {
	alt := strings.NewReplacer("\\", "\\\\", "[", "\\[", "]", "\\]", "\n", " ", "\r", " ").Replace(a.Name)
	return "![" + alt + "](attachment:" + a.ID + ")"
}
func (a *App) receiveImage(w http.ResponseWriter, r *http.Request, noteID string, actor store.Actor) (store.Attachment, error) {
	empty := store.Attachment{}
	if r.MultipartForm == nil {
		r.Body = http.MaxBytesReader(w, r.Body, a.cfg.MaxImageBytes+(64<<10))
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			if r.MultipartForm != nil {
				r.MultipartForm.RemoveAll()
			}
			var max *http.MaxBytesError
			if errors.As(err, &max) {
				return empty, err
			}
			return empty, &HTTPError{400, "invalid_multipart", "Ожидается multipart/form-data с полем file"}
		}
		defer r.MultipartForm.RemoveAll()
	}
	files := r.MultipartForm.File["file"]
	if len(files) != 1 {
		return empty, &HTTPError{422, "invalid_file", "Нужно одно изображение в поле file"}
	}
	for field, parts := range r.MultipartForm.File {
		if field != "file" && len(parts) > 0 {
			return empty, &HTTPError{422, "invalid_file", "Неизвестное поле файла"}
		}
	}
	f, err := files[0].Open()
	if err != nil {
		return empty, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, a.cfg.MaxImageBytes+1))
	if err != nil {
		return empty, err
	}
	if int64(len(data)) > a.cfg.MaxImageBytes {
		return empty, &HTTPError{413, "too_large", "Изображение превышает допустимый размер"}
	}
	mimeType := http.DetectContentType(data)
	extensions := map[string]string{"image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp"}
	ext, ok := extensions[mimeType]
	if !ok {
		return empty, &HTTPError{415, "unsupported_image", "Разрешены PNG, JPEG и WebP"}
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || (format != "png" && format != "jpeg" && format != "webp") {
		return empty, &HTTPError{415, "unsupported_image", "Не удалось прочитать изображение"}
	}
	if config.Width <= 0 || config.Height <= 0 || config.Width > 16000 || config.Height > 16000 || int64(config.Width)*int64(config.Height) > 20000000 {
		return empty, &HTTPError{422, "image_dimensions", "Изображение слишком большое: максимум 20 мегапикселей и 16000 пикселей по стороне"}
	}
	attachment := store.Attachment{ID: store.NewID(), NoteID: noteID, Name: cleanFilename(files[0].Filename), MIME: mimeType, Size: int64(len(data))}
	attachment.StorageKey = attachment.ID + ext
	path := filepath.Join(a.cfg.DataDir, "uploads", attachment.StorageKey)
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return empty, err
	}
	success := false
	defer func() {
		out.Close()
		if !success {
			os.Remove(path)
		}
	}()
	if _, err = out.Write(data); err != nil {
		return empty, err
	}
	if err = out.Sync(); err != nil {
		return empty, err
	}
	if err = out.Close(); err != nil {
		return empty, err
	}
	result, err := a.db.CreateAttachment(r.Context(), attachment, actor, a.cfg.MaxStorageBytes)
	if err != nil {
		return empty, err
	}
	success = true
	return result, nil
}
func (a *App) attachment(w http.ResponseWriter, r *http.Request, noteID, attachmentID string) {
	entry, err := a.db.Attachment(r.Context(), noteID, attachmentID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if entry.StorageKey != filepath.Base(entry.StorageKey) || strings.ContainsAny(entry.StorageKey, "\\/") {
		a.fail(w, r, store.ErrNotFound)
		return
	}
	root, err := os.OpenRoot(filepath.Join(a.cfg.DataDir, "uploads"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	defer root.Close()
	f, err := root.Open(entry.StorageKey)
	if errors.Is(err, os.ErrNotExist) {
		a.fail(w, r, store.ErrNotFound)
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		a.fail(w, r, store.ErrNotFound)
		return
	}
	w.Header().Set("Content-Type", entry.MIME)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("inline", map[string]string{"filename": entry.Name}))
	http.ServeContent(w, r, entry.Name, info.ModTime(), f)
}
func (a *App) removeFiles(entries []store.Attachment) {
	for _, entry := range entries {
		if entry.StorageKey == filepath.Base(entry.StorageKey) && !strings.ContainsAny(entry.StorageKey, "\\/") {
			err := os.Remove(filepath.Join(a.cfg.DataDir, "uploads", entry.StorageKey))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				slog.Warn("could not remove an unreferenced upload")
			}
		}
	}
}

// The detection: says what each file of a repository is.
//
// It reads the repository at the path given as argument and prints one JSON
// line for each file. It skips nothing but the `.git` folder at the root:
// vendored, generated, hidden and documentation files are all listed.
package main

import (
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-enry/go-enry/v2"
	"github.com/go-enry/go-enry/v2/data"
)

// The part of a file that the detection reads.
const readLimit = 64 * 1024

type entry struct {
	Path     string `json:"path"`
	Language string `json:"language"`
	Type     string `json:"type"`
	Binary   bool   `json:"binary"`
	Mime     string `json:"mime"`
	Link     bool   `json:"link"`
}

// The strategies of linguist, without two of them. The modeline is left out:
// with it a file could declare itself to be plain text. The classifier is
// used only to choose between candidates, never to guess from nothing.
var strategies = []enry.Strategy{
	enry.GetLanguagesByFilename,
	enry.GetLanguagesByShebang,
	enry.GetLanguagesByExtension,
	enry.GetLanguagesByXML,
	enry.GetLanguagesByManpage,
	enry.GetLanguagesByContent,
}

func language(name string, content []byte) string {
	var candidates []string
	for _, strategy := range strategies {
		found := strategy(name, content, candidates)
		if len(found) == 1 {
			return found[0]
		}
		if len(found) > 1 {
			candidates = found
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	if ranked := enry.GetLanguagesByClassifier(name, content, candidates); len(ranked) > 0 {
		return ranked[0]
	}
	return candidates[0]
}

func head(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, readLimit))
	return content, err
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: detection <repository>")
	}
	root := os.Args[1]
	out := json.NewEncoder(os.Stdout)

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if rel == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel = filepath.ToSlash(rel)
		if !d.Type().IsRegular() {
			return out.Encode(entry{Path: rel, Link: true})
		}
		content, err := head(path)
		if err != nil {
			return err
		}
		lang := language(filepath.Base(path), content)
		kind := ""
		if lang != "" {
			kind = data.Type(enry.GetLanguageType(lang)).String()
		}
		return out.Encode(entry{
			Path:     rel,
			Language: lang,
			Type:     kind,
			Binary:   enry.IsBinary(content),
			Mime:     http.DetectContentType(content),
		})
	})
	if err != nil {
		log.Fatal(err)
	}
}

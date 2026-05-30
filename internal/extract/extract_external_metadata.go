package extract

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// collect7zListMetadata performs a best-effort `7zz l -slt` and extracts
// compact archive metadata for report rendering.
func collect7zListMetadata(ctx context.Context, binary string, filePath string) *ArchiveMetadata {
	cmd := exec.CommandContext(ctx, binary, "l", "-slt", filePath) //nolint:gosec // G204: binary is resolved from fixed 7-Zip candidate names.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil
	}
	if err := cmd.Start(); err != nil {
		return nil
	}

	meta := &ArchiveMetadata{}
	methods := map[string]struct{}{}
	inHeader := true

	scanner := bufio.NewScanner(stdout)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "----------") {
			inHeader = false
			continue
		}

		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		if inHeader {
			switch key {
			case "Type":
				meta.Type = val
			case "Physical Size":
				meta.PhysicalSize = val
			case "Headers Size":
				meta.HeadersSize = val
			case "Solid":
				meta.Solid = val
			case "Blocks":
				meta.Blocks = val
			}
		}

		switch key {
		case "Method":
			if val != "" {
				methods[val] = struct{}{}
			}
		case "Encrypted":
			if val == "+" || strings.EqualFold(val, "true") {
				meta.HasEncryptedItem = true
			}
		}
	}

	_ = cmd.Wait()
	if scanErr := scanner.Err(); scanErr != nil {
		return nil
	}

	if len(methods) > 0 {
		meta.Methods = make([]string, 0, len(methods))
		for m := range methods {
			meta.Methods = append(meta.Methods, m)
		}
		sort.Strings(meta.Methods)
	}

	if meta.Type == "" && len(meta.Methods) == 0 && meta.PhysicalSize == "" && meta.HeadersSize == "" &&
		meta.Solid == "" && meta.Blocks == "" && !meta.HasEncryptedItem {
		return nil
	}
	return meta
}

// summarizeExtractedDir walks an extracted directory and returns the count and
// total size of regular files so external-tool extraction metrics match the
// in-process ZIP and TAR extractors.
func summarizeExtractedDir(outDir string) (int, int64, error) {
	entriesCount := 0
	totalSize := int64(0)

	err := filepath.Walk(outDir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		entriesCount++
		totalSize += info.Size()
		return nil
	})
	if err != nil {
		return 0, 0, err
	}

	return entriesCount, totalSize, nil
}

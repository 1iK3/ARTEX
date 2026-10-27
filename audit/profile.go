package audit

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ProductType values use the design product enum.
const (
	ProductTypeWebApplication = "web-application"
	ProductTypeMicroservice   = "microservice"
	ProductTypeSDKLibrary     = "sdk-library"
	ProductTypeDesktopClient  = "desktop-client"
	ProductTypeMobileApp      = "mobile-app"
	ProductTypeMiddleware     = "middleware-plugin"
	ProductTypeCLITool        = "cli-tool"
	ProductTypeEmbedded       = "embedded-firmware"
)

// Profile is the deterministic repository profile produced by S1. It is a
// heuristic snapshot, not a semantic understanding of the codebase.
// Warnings records bounded-profile omissions (file-count and oversized-file
// limits); Truncated is true whenever the profile is knowingly incomplete.
type Profile struct {
	Languages    []string `json:"languages"`
	Primary      string   `json:"primary"`
	BuildSystems []string `json:"build_systems"`
	Frameworks   []string `json:"frameworks"`
	Modules      []string `json:"modules"`
	ProductType  string   `json:"product_type"`
	FileCount    int      `json:"file_count"`
	Bytes        int64    `json:"bytes"`
	Warnings     []string `json:"warnings,omitempty"`
	Truncated    bool     `json:"truncated"`
}

const (
	profileFrameworkProbeLimit int64 = 256 << 10
	profileModuleLimit               = 50
)

// ProfileSource inspects an already-acquired snapshot. Tests and vendor
// directories are included according to limits; generated/VCS/build
// directories are always excluded.
func ProfileSource(root string, limits PrescanLimits) (Profile, error) {
	profile := Profile{
		Languages:    []string{},
		BuildSystems: []string{},
		Frameworks:   []string{},
		Modules:      []string{},
		ProductType:  ProductTypeSDKLibrary,
		Warnings:     []string{},
	}
	languageCounts := make(map[string]int)
	modules := make(map[string]struct{})
	buildSystems := make(map[string]struct{})
	frameworks := make(map[string]struct{})
	mainDetected := false
	webEntryDetected := false
	examinedFiles := 0
	oversizedFiles := 0

	err := walkSourceTree(root, limits.IncludeTests, limits.IncludeVendor, func(path, relSlash string) error {
		if limits.MaxFiles > 0 && examinedFiles >= limits.MaxFiles {
			profile.Truncated = true
			profile.Warnings = append(profile.Warnings, fmt.Sprintf(
				"file limit reached: stopped after %d file(s) (max_files=%d)",
				examinedFiles, limits.MaxFiles,
			))
			return filepath.SkipAll
		}
		examinedFiles++

		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("stat source file %s: %w", relSlash, err)
		}
		if limits.MaxFileBytes > 0 && info.Size() > limits.MaxFileBytes {
			profile.Truncated = true
			oversizedFiles++
			profile.Warnings = append(profile.Warnings, fmt.Sprintf(
				"skipped oversized file %s (%d bytes > max_file_bytes=%d)",
				relSlash, info.Size(), limits.MaxFileBytes,
			))
			return nil
		}
		profile.FileCount++
		profile.Bytes += info.Size()

		base := filepath.Base(relSlash)
		for _, system := range buildSystemsForFile(base) {
			buildSystems[system] = struct{}{}
		}

		language := languageForFile(relSlash)
		if language != "" {
			languageCounts[language]++
			module := topLevelModule(relSlash)
			modules[module] = struct{}{}
		}

		if !profileProbeCandidate(base, language) {
			return nil
		}
		content, ok, err := readProfileProbe(path, profileFrameworkProbeLimit)
		if err != nil {
			return fmt.Errorf("read source file %s: %w", relSlash, err)
		}
		if !ok {
			return nil
		}
		for _, framework := range detectFrameworks(content) {
			frameworks[framework] = struct{}{}
		}
		if language != "" && detectMainEntry(relSlash, content) {
			mainDetected = true
		}
		if detectWebEntry(content) {
			webEntryDetected = true
		}
		return nil
	})
	if err != nil {
		return Profile{}, err
	}
	if oversizedFiles > 0 {
		profile.Warnings = append(profile.Warnings, fmt.Sprintf(
			"skipped %d oversized file(s) (max_file_bytes=%d)",
			oversizedFiles, limits.MaxFileBytes,
		))
	}

	type countedLanguage struct {
		name  string
		count int
	}
	ordered := make([]countedLanguage, 0, len(languageCounts))
	for language, count := range languageCounts {
		ordered = append(ordered, countedLanguage{name: language, count: count})
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].count != ordered[j].count {
			return ordered[i].count > ordered[j].count
		}
		return ordered[i].name < ordered[j].name
	})
	for _, item := range ordered {
		profile.Languages = append(profile.Languages, item.name)
	}
	if len(profile.Languages) > 0 {
		profile.Primary = profile.Languages[0]
	}

	for system := range buildSystems {
		profile.BuildSystems = append(profile.BuildSystems, system)
	}
	sort.Strings(profile.BuildSystems)

	for framework := range frameworks {
		profile.Frameworks = append(profile.Frameworks, framework)
	}
	sort.Strings(profile.Frameworks)

	for module := range modules {
		profile.Modules = append(profile.Modules, module)
	}
	sort.Strings(profile.Modules)
	if len(profile.Modules) > profileModuleLimit {
		profile.Modules = profile.Modules[:profileModuleLimit]
	}

	switch {
	case len(profile.Frameworks) > 0 || webEntryDetected:
		profile.ProductType = ProductTypeWebApplication
	case mainDetected:
		profile.ProductType = ProductTypeCLITool
	default:
		profile.ProductType = ProductTypeSDKLibrary
	}
	return profile, nil
}

func buildSystemsForFile(base string) []string {
	lower := strings.ToLower(base)
	switch lower {
	case "pom.xml":
		return []string{"maven"}
	case "build.gradle", "build.gradle.kts":
		return []string{"gradle"}
	case "package.json":
		return []string{"npm"}
	case "pnpm-lock.yaml":
		return []string{"pnpm"}
	case "yarn.lock":
		return []string{"yarn"}
	case "go.mod":
		return []string{"go"}
	case "cargo.toml":
		return []string{"cargo"}
	case "cmakelists.txt":
		return []string{"cmake"}
	case "makefile", "gnumakefile":
		return []string{"make"}
	case "configure.ac", "configure.in":
		return []string{"autotools"}
	case "pyproject.toml", "requirements.txt", "setup.py":
		return []string{"python"}
	case "composer.json":
		return []string{"composer"}
	case "gemfile":
		return []string{"bundler"}
	}
	if strings.HasSuffix(lower, ".csproj") {
		return []string{"dotnet"}
	}
	if strings.HasPrefix(lower, "requirements") && strings.HasSuffix(lower, ".txt") {
		return []string{"python"}
	}
	return nil
}

func topLevelModule(relSlash string) string {
	if idx := strings.IndexByte(relSlash, '/'); idx >= 0 {
		module := relSlash[:idx]
		if module != "" {
			return module
		}
	}
	return "."
}

func profileProbeCandidate(base, language string) bool {
	if language != "" {
		return true
	}
	return len(buildSystemsForFile(base)) > 0
}

func readProfileProbe(path string, limit int64) (string, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return "", false, err
	}
	for _, b := range data {
		if b == 0 {
			return "", false, nil
		}
	}
	return strings.ToLower(string(data)), true, nil
}

type frameworkRule struct {
	name   string
	tokens []string
}

var frameworkRules = []frameworkRule{
	{name: "Spring", tokens: []string{"org.springframework", "spring-boot", "@springbootapplication"}},
	{name: "Django", tokens: []string{"django"}},
	{name: "Flask", tokens: []string{"flask"}},
	{name: "FastAPI", tokens: []string{"fastapi"}},
	{name: "Express", tokens: []string{`"express"`, `'express'`}},
	{name: "NestJS", tokens: []string{"@nestjs/core", "@nestjs/common"}},
	{name: "Next.js", tokens: []string{`"next"`, `'next'`}},
	{name: "Gin", tokens: []string{"github.com/gin-gonic/gin"}},
	{name: "Echo", tokens: []string{"github.com/labstack/echo"}},
	{name: "Fiber", tokens: []string{"github.com/gofiber/fiber"}},
	{name: "Actix", tokens: []string{"actix-web", "actix_web"}},
	{name: "Axum", tokens: []string{"axum"}},
	{name: "Rails", tokens: []string{`gem "rails"`, `gem 'rails'`, `"rails"`, `'rails'`}},
	{name: "ASP.NET", tokens: []string{"microsoft.aspnetcore", "microsoft.net.sdk.web"}},
}

func detectFrameworks(content string) []string {
	var found []string
	for _, rule := range frameworkRules {
		for _, token := range rule.tokens {
			if strings.Contains(content, token) {
				found = append(found, rule.name)
				break
			}
		}
	}
	return found
}

var webEntryMarkers = []string{
	"@webservlet",
	"javax.servlet",
	"jakarta.servlet",
	"http.listenandserve(",
	"http.listenandservetls(",
	"http.createserver(",
	"app.listen(",
	"uvicorn.run(",
	"hypercorn",
	"gunicorn",
	"webapplication.createbuilder(",
	"axum::serve(",
	"actix_web::http",
}

func detectWebEntry(content string) bool {
	for _, marker := range webEntryMarkers {
		if strings.Contains(content, marker) {
			return true
		}
	}
	return false
}

var mainFileNames = map[string]struct{}{
	"main.go":     {},
	"main.py":     {},
	"main.rs":     {},
	"main.c":      {},
	"main.cc":     {},
	"main.cpp":    {},
	"main.cxx":    {},
	"main.swift":  {},
	"main.kt":     {},
	"main.java":   {},
	"program.cs":  {},
	"program.fs":  {},
	"program.vb":  {},
	"index.js":    {}, // Conservative: an index entry is only treated as main when content has a main marker.
	"index.ts":    {},
	"__main__.py": {},
}

var mainContentMarkers = []string{
	"func main(",
	"public static void main(",
	"static void main(",
	"if __name__ == \"__main__\"",
	"if __name__ == '__main__'",
	"fn main(",
	"int main(",
	"void main(",
	"static async task main(",
	"static void main(string",
}

func detectMainEntry(relSlash, content string) bool {
	base := strings.ToLower(filepath.Base(relSlash))
	if _, ok := mainFileNames[base]; ok {
		// index.js/index.ts are common library entry files too. Require a
		// strong main marker for those two names.
		if base != "index.js" && base != "index.ts" {
			return true
		}
	}
	for _, marker := range mainContentMarkers {
		if strings.Contains(content, marker) {
			return true
		}
	}
	return false
}

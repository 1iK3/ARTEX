package audit

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfileJavaMaven(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "pom.xml"), `<project>
  <dependencies>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
  </dependencies>
</project>
`)
	writeAuditTestFile(t, filepath.Join(root, "src", "main", "java", "com", "acme", "A.java"), "package com.acme;\nclass A {}\n")
	writeAuditTestFile(t, filepath.Join(root, "src", "test", "java", "com", "acme", "ATest.java"), "class ATest {}\n")

	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatalf("ProfileSource: %v", err)
	}
	if !equalStrings(profile.Languages, []string{Java}) {
		t.Fatalf("Languages = %v, want [java]", profile.Languages)
	}
	if profile.Primary != Java {
		t.Fatalf("Primary = %q, want java", profile.Primary)
	}
	if !equalStrings(profile.BuildSystems, []string{"maven"}) {
		t.Fatalf("BuildSystems = %v, want [maven]", profile.BuildSystems)
	}
	if !equalStrings(profile.Frameworks, []string{"Spring"}) {
		t.Fatalf("Frameworks = %v, want [Spring]", profile.Frameworks)
	}
	if !equalStrings(profile.Modules, []string{"src"}) {
		t.Fatalf("Modules = %v, want [src]", profile.Modules)
	}
	if profile.ProductType != "web-application" {
		t.Fatalf("ProductType = %q, want web-application", profile.ProductType)
	}
	if profile.FileCount != 2 {
		t.Fatalf("FileCount = %d, want 2", profile.FileCount)
	}
	if profile.Bytes <= 0 {
		t.Fatal("expected positive Bytes")
	}
}

func TestProfileNodeTypeScript(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "package.json"), `{
  "name": "demo",
  "dependencies": {"express": "^4.19.0", "next": "14.0.0"}
}
`)
	writeAuditTestFile(t, filepath.Join(root, "src", "app.ts"), "import express from 'express';\nconst app = express();\n")

	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatalf("ProfileSource: %v", err)
	}
	if !equalStrings(profile.Languages, []string{TypeScript}) {
		t.Fatalf("Languages = %v, want [typescript]", profile.Languages)
	}
	if profile.Primary != TypeScript {
		t.Fatalf("Primary = %q, want typescript", profile.Primary)
	}
	if !equalStrings(profile.BuildSystems, []string{"npm"}) {
		t.Fatalf("BuildSystems = %v, want [npm]", profile.BuildSystems)
	}
	if !equalStrings(profile.Frameworks, []string{"Express", "Next.js"}) {
		t.Fatalf("Frameworks = %v, want [Express Next.js]", profile.Frameworks)
	}
	if !equalStrings(profile.Modules, []string{"src"}) {
		t.Fatalf("Modules = %v, want [src]", profile.Modules)
	}
	if profile.ProductType != "web-application" {
		t.Fatalf("ProductType = %q, want web-application", profile.ProductType)
	}
}

func TestProfilePythonDjango(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "requirements.txt"), "Django==5.0.0\n")
	writeAuditTestFile(t, filepath.Join(root, "app.py"), "from django.http import HttpResponse\n")

	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatalf("ProfileSource: %v", err)
	}
	if !equalStrings(profile.Languages, []string{Python}) {
		t.Fatalf("Languages = %v, want [python]", profile.Languages)
	}
	if !equalStrings(profile.BuildSystems, []string{"python"}) {
		t.Fatalf("BuildSystems = %v, want [python]", profile.BuildSystems)
	}
	if !equalStrings(profile.Frameworks, []string{"Django"}) {
		t.Fatalf("Frameworks = %v, want [Django]", profile.Frameworks)
	}
	if !equalStrings(profile.Modules, []string{"."}) {
		t.Fatalf("Modules = %v, want [.]", profile.Modules)
	}
	if profile.ProductType != "web-application" {
		t.Fatalf("ProductType = %q, want web-application", profile.ProductType)
	}
}

func TestProfileGoCLI(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "go.mod"), "module example.com/demo\n\ngo 1.22\n")
	writeAuditTestFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")
	writeAuditTestFile(t, filepath.Join(root, "internal", "server", "server.go"), "package server\n")

	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatalf("ProfileSource: %v", err)
	}
	if !equalStrings(profile.Languages, []string{Go}) {
		t.Fatalf("Languages = %v, want [go]", profile.Languages)
	}
	if !equalStrings(profile.BuildSystems, []string{"go"}) {
		t.Fatalf("BuildSystems = %v, want [go]", profile.BuildSystems)
	}
	if len(profile.Frameworks) != 0 {
		t.Fatalf("Frameworks = %v, want none", profile.Frameworks)
	}
	if !equalStrings(profile.Modules, []string{".", "internal"}) {
		t.Fatalf("Modules = %v, want [. internal]", profile.Modules)
	}
	if profile.ProductType != ProductTypeCLITool {
		t.Fatalf("ProductType = %q, want cli-tool", profile.ProductType)
	}
}

func TestProfileMixed(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "pom.xml"), "<project><dependency>org.springframework</dependency></project>\n")
	writeAuditTestFile(t, filepath.Join(root, "package.json"), `{"dependencies":{"express":"4"}}`)
	writeAuditTestFile(t, filepath.Join(root, "src", "main", "java", "A.java"), "class A {}\n")
	writeAuditTestFile(t, filepath.Join(root, "src", "app.ts"), "import express from 'express';\n")

	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatalf("ProfileSource: %v", err)
	}
	if !equalStrings(profile.Languages, []string{Java, TypeScript}) {
		t.Fatalf("Languages = %v, want [java typescript]", profile.Languages)
	}
	if profile.Primary != Java {
		t.Fatalf("Primary = %q, want java (count tie, lexical order)", profile.Primary)
	}
	if !equalStrings(profile.BuildSystems, []string{"maven", "npm"}) {
		t.Fatalf("BuildSystems = %v, want [maven npm]", profile.BuildSystems)
	}
	if !equalStrings(profile.Frameworks, []string{"Express", "Spring"}) {
		t.Fatalf("Frameworks = %v, want [Express Spring]", profile.Frameworks)
	}
	if !equalStrings(profile.Modules, []string{"src"}) {
		t.Fatalf("Modules = %v, want [src]", profile.Modules)
	}
	if profile.FileCount != 4 {
		t.Fatalf("FileCount = %d, want 4", profile.FileCount)
	}
}

func TestProfileExcludesAndIncludeFlags(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "src", "main", "java", "A.java"), "class A {}\n")
	writeAuditTestFile(t, filepath.Join(root, "src", "test", "java", "ATest.java"), "class ATest {}\n")
	writeAuditTestFile(t, filepath.Join(root, "testdata", "fixture.py"), "print(1)\n")
	writeAuditTestFile(t, filepath.Join(root, "vendor", "v.go"), "package vendor\n")
	writeAuditTestFile(t, filepath.Join(root, "node_modules", "x.js"), "module.exports = 1\n")
	writeAuditTestFile(t, filepath.Join(root, "dist", "bundle.js"), "bundled\n")
	writeAuditTestFile(t, filepath.Join(root, "build", "B.java"), "class B {}\n")

	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatalf("ProfileSource: %v", err)
	}
	if !equalStrings(profile.Languages, []string{Java}) || profile.FileCount != 1 {
		t.Fatalf("default profile = languages %v files %d, want [java] 1", profile.Languages, profile.FileCount)
	}

	profile, err = ProfileSource(root, PrescanLimits{IncludeTests: true, IncludeVendor: true})
	if err != nil {
		t.Fatalf("ProfileSource include flags: %v", err)
	}
	if !equalStrings(profile.Languages, []string{Java, Go, Python}) {
		t.Fatalf("include languages = %v, want [java go python]", profile.Languages)
	}
	if profile.FileCount != 4 {
		t.Fatalf("include FileCount = %d, want 4", profile.FileCount)
	}
	if !equalStrings(profile.Modules, []string{"src", "testdata", "vendor"}) {
		t.Fatalf("include Modules = %v, want [src testdata vendor]", profile.Modules)
	}
}

func TestProfileEmpty(t *testing.T) {
	profile, err := ProfileSource(t.TempDir(), PrescanLimits{})
	if err != nil {
		t.Fatalf("ProfileSource: %v", err)
	}
	if len(profile.Languages) != 0 || profile.Primary != "" {
		t.Fatalf("empty profile languages = %v primary = %q", profile.Languages, profile.Primary)
	}
	if profile.Languages == nil || profile.BuildSystems == nil || profile.Frameworks == nil || profile.Modules == nil {
		t.Fatalf("profile slices must be non-nil: %+v", profile)
	}
	if profile.ProductType != ProductTypeSDKLibrary {
		t.Fatalf("ProductType = %q, want sdk-library", profile.ProductType)
	}
	if profile.FileCount != 0 || profile.Bytes != 0 {
		t.Fatalf("FileCount/Bytes = %d/%d, want 0/0", profile.FileCount, profile.Bytes)
	}
}

func TestProfileLimits(t *testing.T) {
	t.Run("max files", func(t *testing.T) {
		root := t.TempDir()
		for _, name := range []string{"a.go", "b.go", "c.go"} {
			writeAuditTestFile(t, filepath.Join(root, name), "package p\n")
		}
		profile, err := ProfileSource(root, PrescanLimits{MaxFiles: 2})
		if err != nil {
			t.Fatalf("ProfileSource: %v", err)
		}
		if profile.FileCount != 2 || !profile.Truncated {
			t.Fatalf("FileCount/Truncated = %d/%v, want 2/true", profile.FileCount, profile.Truncated)
		}
		if !strings.Contains(strings.Join(profile.Warnings, "\n"), "file limit") ||
			!strings.Contains(strings.Join(profile.Warnings, "\n"), "2") {
			t.Fatalf("Warnings = %v, want a file-limit warning with a count", profile.Warnings)
		}
		if !equalStrings(profile.Languages, []string{Go}) {
			t.Fatalf("Languages = %v, want [go]", profile.Languages)
		}

		exact, err := ProfileSource(root, PrescanLimits{MaxFiles: 3})
		if err != nil {
			t.Fatalf("ProfileSource exact limit: %v", err)
		}
		if exact.Truncated || len(exact.Warnings) != 0 {
			t.Fatalf("exact limit unexpectedly truncated: %+v", exact)
		}
	})

	t.Run("max file bytes", func(t *testing.T) {
		root := t.TempDir()
		writeAuditTestFile(t, filepath.Join(root, "big.py"), strings.Repeat("x", 100))
		writeAuditTestFile(t, filepath.Join(root, "small.py"), "x = 1\n")
		profile, err := ProfileSource(root, PrescanLimits{MaxFileBytes: 10})
		if err != nil {
			t.Fatalf("ProfileSource: %v", err)
		}
		if profile.FileCount != 1 || !profile.Truncated {
			t.Fatalf("FileCount/Truncated = %d/%v, want 1/true", profile.FileCount, profile.Truncated)
		}
		joined := strings.Join(profile.Warnings, "\n")
		if !strings.Contains(joined, "oversized") || !strings.Contains(joined, "1") || !strings.Contains(joined, "big.py") {
			t.Fatalf("Warnings = %v, want oversized count/path", profile.Warnings)
		}
		if !equalStrings(profile.Languages, []string{Python}) {
			t.Fatalf("Languages = %v, want [python]", profile.Languages)
		}
	})
}

func TestProfileNoIdentifiableLanguages(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "README.md"), "# docs only\n")
	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatalf("ProfileSource: %v", err)
	}
	if len(profile.Languages) != 0 || profile.Primary != "" {
		t.Fatalf("languages/primary = %v/%q, want empty", profile.Languages, profile.Primary)
	}
	if profile.Languages == nil || profile.Warnings == nil {
		t.Fatalf("profile slices must be non-nil: %+v", profile)
	}
	if profile.ProductType != ProductTypeSDKLibrary {
		t.Fatalf("ProductType = %q, want sdk-library", profile.ProductType)
	}
	if _, err := BuildPlan(profile, Config{Depth: DepthQuick, CWEScope: CWEScopeCore}, mustLoadRegistry(t)); err == nil {
		t.Fatal("BuildPlan must fail clearly without identifiable languages")
	} else if !strings.Contains(err.Error(), "无法确定审计语言") {
		t.Fatalf("BuildPlan error = %v", err)
	}
}

func TestProfileMissingRoot(t *testing.T) {
	if _, err := ProfileSource(filepath.Join(t.TempDir(), "missing"), PrescanLimits{}); err == nil {
		t.Fatal("expected missing root error")
	}
}

func TestProfileLanguageExtensions(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"A.kt":    "class A\n",
		"a.php":   "<?php\n",
		"a.rb":    "puts 1\n",
		"A.cs":    "class A {}\n",
		"A.swift": "let a = 1\n",
		"A.scala": "object A {}\n",
		"a.sh":    "echo hi\n",
		"a.c":     "int main(void) { return 0; }\n",
		"a.h":     "#pragma once\n",
		"a.cpp":   "int main() { return 0; }\n",
		"b.cc":    "int b() { return 0; }\n",
		"c.cxx":   "int c() { return 0; }\n",
		"d.hpp":   "#pragma once\n",
	}
	for name, body := range files {
		writeAuditTestFile(t, filepath.Join(root, name), body)
	}
	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatalf("ProfileSource: %v", err)
	}
	want := []string{CPP, C, "csharp", "kotlin", "php", "ruby", "scala", "shell", "swift"}
	if !equalStrings(profile.Languages, want) {
		t.Fatalf("Languages = %v, want %v", profile.Languages, want)
	}
	if profile.Primary != CPP {
		t.Fatalf("Primary = %q, want cpp", profile.Primary)
	}
}

func TestProfileWebFrameworkHeuristics(t *testing.T) {
	tests := []struct {
		name       string
		files      map[string]string
		frameworks []string
		product    string
	}{
		{
			name: "go gin",
			files: map[string]string{
				"go.mod":  "module x\n\nrequire github.com/gin-gonic/gin v1.9.0\n",
				"main.go": "package main\nimport _ \"github.com/gin-gonic/gin\"\nfunc main() {}\n",
			},
			frameworks: []string{"Gin"},
			product:    "web-application",
		},
		{
			name: "rust actix",
			files: map[string]string{
				"Cargo.toml":  "[dependencies]\nactix-web = \"4\"\n",
				"src/main.rs": "use actix_web::App;\nfn main() {}\n",
			},
			frameworks: []string{"Actix"},
			product:    "web-application",
		},
		{
			name: "python fastapi",
			files: map[string]string{
				"app.py": "from fastapi import FastAPI\napp = FastAPI()\n",
			},
			frameworks: []string{"FastAPI"},
			product:    "web-application",
		},
		{
			name: "dotnet",
			files: map[string]string{
				"App.csproj": `<Project Sdk="Microsoft.NET.Sdk.Web"><ItemGroup><PackageReference Include="Microsoft.AspNetCore.Mvc" /></ItemGroup></Project>`,
				"Program.cs": "public class Program { public static void Main() {} }\n",
			},
			frameworks: []string{"ASP.NET"},
			product:    "web-application",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for name, body := range tc.files {
				writeAuditTestFile(t, filepath.Join(root, filepath.FromSlash(name)), body)
			}
			profile, err := ProfileSource(root, PrescanLimits{})
			if err != nil {
				t.Fatalf("ProfileSource: %v", err)
			}
			if !equalStrings(profile.Frameworks, tc.frameworks) {
				t.Fatalf("Frameworks = %v, want %v", profile.Frameworks, tc.frameworks)
			}
			if profile.ProductType != tc.product {
				t.Fatalf("ProductType = %q, want %q", profile.ProductType, tc.product)
			}
		})
	}
}

func TestProfileBuildSystems(t *testing.T) {
	root := t.TempDir()
	markers := []string{
		"pom.xml",
		"build.gradle",
		"build.gradle.kts",
		"package.json",
		"pnpm-lock.yaml",
		"yarn.lock",
		"go.mod",
		"Cargo.toml",
		"CMakeLists.txt",
		"Makefile",
		"configure.ac",
		"pyproject.toml",
		"requirements.txt",
		"setup.py",
		"App.csproj",
		"composer.json",
		"Gemfile",
	}
	for _, marker := range markers {
		writeAuditTestFile(t, filepath.Join(root, marker), "x\n")
	}
	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatalf("ProfileSource: %v", err)
	}
	want := []string{"autotools", "bundler", "cargo", "cmake", "composer", "dotnet", "go", "gradle", "make", "maven", "npm", "pnpm", "python", "yarn"}
	if !equalStrings(profile.BuildSystems, want) {
		t.Fatalf("BuildSystems = %v, want %v", profile.BuildSystems, want)
	}
	if profile.FileCount != len(markers) {
		t.Fatalf("FileCount = %d, want %d", profile.FileCount, len(markers))
	}
}

func TestProfileModulesCap(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 55; i++ {
		dir := fmt.Sprintf("m%02d", i)
		writeAuditTestFile(t, filepath.Join(root, dir, "f.go"), "package p\n")
	}
	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatalf("ProfileSource: %v", err)
	}
	if len(profile.Modules) != 50 {
		t.Fatalf("Modules length = %d, want 50", len(profile.Modules))
	}
	if profile.Modules[0] != "m00" || profile.Modules[49] != "m49" {
		t.Fatalf("Modules = %v, want sorted first 50", profile.Modules)
	}
	if profile.FileCount != 55 {
		t.Fatalf("FileCount = %d, want 55", profile.FileCount)
	}
}

package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/core/baseline"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/words/mask"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
)

// TreeNode represents a node in the path tree
type TreeNode struct {
	Name     string
	Children map[string]*TreeNode
	Result   *baseline.Baseline // nil for directory nodes
	IsLeaf   bool
}

// NewTreeNode creates a new tree node
func NewTreeNode(name string) *TreeNode {
	return &TreeNode{
		Name:     name,
		Children: make(map[string]*TreeNode),
		IsLeaf:   false,
	}
}

// AddPath adds a path to the tree
func (tn *TreeNode) AddPath(parts []string, result *baseline.Baseline) {
	if len(parts) == 0 {
		tn.Result = result
		tn.IsLeaf = true
		return
	}

	part := parts[0]
	if part == "" {
		if len(parts) > 1 {
			tn.AddPath(parts[1:], result)
		} else {
			tn.Result = result
			tn.IsLeaf = true
		}
		return
	}

	if _, exists := tn.Children[part]; !exists {
		tn.Children[part] = NewTreeNode(part)
	}

	tn.Children[part].AddPath(parts[1:], result)
}

// RenderTree renders the tree structure
func (tn *TreeNode) RenderTree(prefix string, isLast bool, color bool) string {
	var sb strings.Builder

	if tn.Name != "" {
		connector := "├── "
		if isLast {
			connector = "└── "
		}

		sb.WriteString(prefix)
		sb.WriteString(connector)

		if tn.IsLeaf && tn.Result != nil {
			// Leaf node with result
			if color {
				sb.WriteString(tn.Result.ColorString())
			} else {
				sb.WriteString(tn.Result.String())
			}
		} else {
			// Directory node
			sb.WriteString(tn.Name)
			if !strings.HasSuffix(tn.Name, "/") {
				sb.WriteString("/")
			}
		}
		sb.WriteString("\n")
	}

	// Sort children for consistent output
	var keys []string
	for k := range tn.Children {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i, key := range keys {
		child := tn.Children[key]
		isLastChild := i == len(keys)-1

		newPrefix := prefix
		if tn.Name != "" {
			if isLast {
				newPrefix += "    "
			} else {
				newPrefix += "│   "
			}
		}

		sb.WriteString(child.RenderTree(newPrefix, isLastChild, color))
	}

	return sb.String()
}

func Format(opts Option) {
	var content []byte
	var err error
	if opts.Format == "stdin" {
		content, err = io.ReadAll(os.Stdin)
	} else {
		content, err = os.ReadFile(opts.Format)
	}

	if err != nil {
		return
	}

	// Group by host:port instead of just host
	group := make(map[string]map[string]*baseline.Baseline)
	for _, line := range bytes.Split(bytes.TrimSpace(content), []byte("\n")) {
		var result baseline.Baseline
		err := json.Unmarshal(line, &result)
		if err != nil {
			logs.Log.Error(err.Error())
			return
		}
		result.Url, err = url.Parse(result.UrlString)
		if err != nil {
			continue
		}

		// Use host:port as the key
		hostPort := result.Url.Host
		if result.Url.Port() == "" {
			if result.Url.Scheme == "https" {
				hostPort += ":443"
			} else if result.Url.Scheme == "http" {
				hostPort += ":80"
			}
		}

		if _, exists := group[hostPort]; !exists {
			group[hostPort] = make(map[string]*baseline.Baseline)
		}
		group[hostPort][result.Path] = &result
	}

	// Default to tree mode if not specified
	outputProbe := opts.OutputProbe
	if outputProbe == "" {
		outputProbe = "tree"
	}

	if outputProbe == "tree" {
		formatTree(group, opts)
	} else if outputProbe == "full" {
		formatFull(group, opts)
	} else {
		// Custom probe output
		formatProbe(group, opts, outputProbe)
	}
}

// formatTree renders results in tree structure
func formatTree(group map[string]map[string]*baseline.Baseline, opts Option) {
	// Sort host:port for consistent output
	var hosts []string
	for host := range group {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	for _, host := range hosts {
		results := group[host]

		// Build tree for this host
		root := NewTreeNode("")
		for path, result := range results {
			if !opts.Fuzzy && result.IsFuzzy {
				continue
			}

			// Split path into parts
			parts := strings.Split(strings.Trim(path, "/"), "/")
			if path == "/" {
				parts = []string{"/"}
			}

			root.AddPath(parts, result)
		}

		// Print host header
		logs.Log.Console(fmt.Sprintf("\n%s\n", host))

		// Render tree
		logs.Log.Console(root.RenderTree("", true, !opts.NoColor))
	}
}

// formatFull renders results in full/original format
func formatFull(group map[string]map[string]*baseline.Baseline, opts Option) {
	for _, results := range group {
		for _, result := range results {
			if !opts.Fuzzy && result.IsFuzzy {
				continue
			}
			if !opts.NoColor {
				logs.Log.Console(result.ColorString() + "\n")
			} else {
				logs.Log.Console(result.String() + "\n")
			}
		}
	}
}

// formatProbe renders results with custom probe fields
func formatProbe(group map[string]map[string]*baseline.Baseline, opts Option, probeFields string) {
	probes := strings.Split(probeFields, ",")
	for _, results := range group {
		for _, result := range results {
			if !opts.Fuzzy && result.IsFuzzy {
				continue
			}
			logs.Log.Console(result.ProbeOutput(probes) + "\n")
		}
	}
}

func PrintPreset() {
	logs.Log.Console("internal rules:\n")
	for name, rule := range pkg.Rules {
		logs.Log.Consolef("\t%s\t%d rules\n", name, len(strings.Split(rule, "\n")))
	}

	logs.Log.Console("\ninternal dicts:\n")
	for name, dict := range pkg.Dicts {
		logs.Log.Consolef("\t%s\t%d items\n", name, len(dict))
	}

	logs.Log.Console("\ninternal words keyword:\n")
	for name, words := range mask.SpecialWords {
		logs.Log.Consolef("\t%s\t%d words\n", name, len(words))
	}

	logs.Log.Console("\ninternal extractor:\n")
	for name, _ := range pkg.ExtractRegexps {
		logs.Log.Consolef("\t%s\n", name)
	}

	logs.Log.Console("\ninternal fingers:\n")
	for name, engine := range pkg.FingerEngine.EnginesImpl {
		logs.Log.Consolef("\t%s\t%d fingerprints \n", name, engine.Len())
	}

	logs.Log.Consolef("\nload %d active path\n", len(pkg.ActivePath))
}

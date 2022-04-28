package main

import (
	"bytes"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"
	yamlv3 "gopkg.in/yaml.v3"
)

//go:embed packetbeat.reference.yml
var packetbeatRefYaml []byte

func main() {
	root := flag.String("root", "", "specify package root")
	flag.Parse()
	if *root == "" {
		flag.Usage()
		os.Exit(2)
	}

	file, err := parser.ParseBytes(packetbeatRefYaml, parser.ParseComments)
	if err != nil {
		log.Fatal(err)
	}
	if len(file.Docs) == 0 {
		log.Fatal("no docs")
	}
	v := newProtocolVisitor("packetbeat.protocols")
	for _, doc := range file.Docs {
		ast.Walk(v, doc)
	}

	for id, name := range v.names {
		stream := filepath.Join(*root, "data_stream", getName(name))
		p := v.protocols[id]
		p = append(protocol{dataStreamOption, pipelineOption}, p...)
		p = append(p, processorsOption, tagsOption)
		err = writeHandlBars(name, p, stream)
		if err != nil {
			log.Fatalf("failed writing %s handlebars: %v", name, err)
		}
		err = writeManifest(name, p, stream)
		if err != nil {
			log.Fatalf("failed writing %s manifest: %v", name, err)
		}
	}
}

func writeHandlBars(name string, p protocol, root string) (err error) {
	f, err := os.Create(filepath.Join(root, "agent", "stream", getName(name)+".yml.hbs"))
	if err != nil {
		return err
	}
	defer func() {
		if err == nil {
			err = f.Close()
		}
	}()

	fmt.Fprintf(f, "type: %s\n", name)
	for _, o := range p {
		if exclude[o.name] {
			continue
		}
		always := o.name == "ports" || o.required
		if !always {
			fmt.Fprintf(f, "{{#if %s}}\n", label(o.name))
		}
		switch o.value.(type) {
		case *ast.SequenceNode:
			fmt.Fprintf(f, `%[1]s:
{{#each %[2]s as |%[3]s|}}
  - {{%[3]s}}
{{/each}}
`, o.name, label(o.name), elem(o.name))
		default:
			if o.name == "processors" {
				fmt.Fprintf(f, "%[1]s:\n{{%[1]s}}\n", o.name)
			} else {
				fmt.Fprintf(f, "%[1]s: {{%[1]s}}\n", o.name)
			}
		}
		if !always {
			fmt.Fprintln(f, "{{/if}}")
		}
	}
	fmt.Fprintln(f, `{{#if processes}}
procs:
  enabled: true
  monitored:
    {{#each processes as |process|}}
    - cmdline_grep: {{process}}
    {{/each}}
{{/if}}
{{#if interface}}
interface:
{{#if (contains ".pcap" interface)}}
  file: {{interface}}
{{else}}
  device: {{interface}}
{{/if}}
{{/if}}`)

	return nil
}

func writeManifest(name string, p protocol, root string) (err error) {
	file, err := parser.ParseFile(filepath.Join(root, "manifest.yml"), parser.ParseComments)
	if err != nil {
		return err
	}

	vars, _ := getNode(file, "$.streams[0].vars", ast.SequenceType).(*ast.SequenceNode)
	if vars == nil {
		stream := getNode(file, "$.streams", ast.SequenceType).(*ast.SequenceNode)
		col := stream.GetToken().Position.Column + 2
		lab := ast.String(&token.Token{Value: "vars", Position: &token.Position{Column: col}})
		vars = ast.Sequence(&token.Token{Position: &token.Position{Column: col}}, false)
		varMap := ast.MappingValue(&token.Token{}, lab, vars)
		stream.Values[0].(*ast.MappingNode).Values = append(stream.Values[0].(*ast.MappingNode).Values, varMap)
	}
	col := vars.GetToken().Position.Column + 2
	for _, o := range p {
		if exclude[o.name] || o.name == "ports" {
			continue
		}

		title := o.title
		if title == "" {
			title = strings.Title(strings.ReplaceAll(o.name, "_", " "))
		}
		mappings := []*ast.MappingValueNode{
			ast.MappingValue(&token.Token{},
				ast.String(&token.Token{Value: "name", Position: &token.Position{Column: col}}),
				ast.String(&token.Token{Value: o.name, Position: &token.Position{Column: col}}),
			),
			ast.MappingValue(&token.Token{},
				ast.String(&token.Token{Value: "type", Position: &token.Position{Column: col}}),
				ast.String(&token.Token{Value: typeFor(o.node.(*ast.MappingValueNode).Value), Position: &token.Position{Column: col + 1}}),
			),
			ast.MappingValue(&token.Token{},
				ast.String(&token.Token{Value: "title", Position: &token.Position{Column: col}}),
				ast.String(&token.Token{Value: title, Position: &token.Position{Column: col + 1}}),
			),
			ast.MappingValue(&token.Token{},
				ast.String(&token.Token{Value: "description", Position: &token.Position{Column: col}}),
				ast.String(&token.Token{Value: o.comment, Position: &token.Position{Column: col}}),
			),
			ast.MappingValue(&token.Token{},
				ast.String(&token.Token{Value: "show_user", Position: &token.Position{Column: col}}),
				ast.Bool(&token.Token{Value: fmt.Sprint(false || o.showUser), Position: &token.Position{Column: col + 1}}),
			),
			ast.MappingValue(&token.Token{},
				ast.String(&token.Token{Value: "multi", Position: &token.Position{Column: col}}),
				ast.Bool(&token.Token{Value: fmt.Sprint(o.node.(*ast.MappingValueNode).Value.Type() == ast.SequenceType), Position: &token.Position{Column: col + 1}}),
			),
			ast.MappingValue(&token.Token{},
				ast.String(&token.Token{Value: "required", Position: &token.Position{Column: col}}),
				ast.Bool(&token.Token{Value: fmt.Sprint(false || o.required), Position: &token.Position{Column: col}}),
			),
		}
		if o.deflt != nil {
			mappings = append(mappings, ast.MappingValue(&token.Token{},
				ast.String(&token.Token{Value: "default", Position: &token.Position{Column: col}}),
				ast.String(&token.Token{Value: "network_traffic." + o.deflt(name), Position: &token.Position{Column: col}}),
			))
		}
		varMap := ast.Mapping(&token.Token{}, false, mappings...)
		vars.Values = append(vars.Values, varMap)
	}

	f, err := os.Create(filepath.Join(root, "manifest.yml"))
	if err != nil {
		return err
	}

	// The AST manipulation has caused some indentation errors that are
	// troublesome to fix correctly, so just round-trip the data through
	// the yaml package used by elastic-package.
	var buf bytes.Buffer
	fmt.Fprint(&buf, file)
	var m yamlv3.Node
	err = yamlv3.Unmarshal(buf.Bytes(), &m)
	if err != nil {
		return err
	}
	enc := yamlv3.NewEncoder(f)
	enc.SetIndent(2)
	err = enc.Encode(&m)
	if err != nil {
		return err
	}

	return f.Close()
}

func getNode(f *ast.File, path string, typ ast.NodeType) ast.Node {
	v := &targetVisitor{target: path, typ: typ}
	for _, d := range f.Docs {
		ast.Walk(v, d)
		if v.node != nil {
			break
		}
	}
	return v.node
}

type targetVisitor struct {
	target string
	typ    ast.NodeType
	node   ast.Node
}

func (v *targetVisitor) Visit(n ast.Node) ast.Visitor {
	if n.GetPath() == v.target && n.Type() == v.typ {
		v.node = n
		return nil
	}
	return v
}

func newProtocolVisitor(target string) *protocolVisitor {
	return &protocolVisitor{
		target:       target,
		protocolToID: make(map[string]int),
		protocols:    make(map[int]protocol),
	}
}

type protocolVisitor struct {
	target string

	names        []string
	protocolToID map[string]int
	protocols    map[int]protocol
}

type protocol []option

type option struct {
	name    string
	node    ast.Node
	value   ast.Node
	comment string

	// Manually set.
	title    string
	required bool
	showUser bool
	deflt    func(string) string
}

var pipelineOption = func() option {
	name := "pipeline"
	comment := "Optional ingest pipeline. By default no pipeline will be used."
	col := 0
	m := ast.MappingValue(&token.Token{},
		ast.String(&token.Token{Value: name, Position: &token.Position{Column: col}}),
		ast.String(&token.Token{Value: "", Position: &token.Position{Column: col}}),
	)
	return option{
		name:    name,
		node:    m,
		value:   m.Value,
		comment: comment,
	}
}()

var processorsOption = func() option {
	name := "processors"
	comment := "Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. This executes in the agent before the logs are parsed. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details."
	col := 0
	m := ast.MappingValue(&token.Token{},
		ast.String(&token.Token{Value: name, Position: &token.Position{Column: col}}),
		&ast.MappingNode{IsFlowStyle: true},
	)
	return option{
		name:    name,
		node:    m,
		value:   m.Value,
		comment: comment,
	}
}()

var tagsOption = func() option {
	name := "tags"
	comment := "Tags to include in the published event."
	col := 0
	m := ast.MappingValue(&token.Token{},
		ast.String(&token.Token{Value: name, Position: &token.Position{Column: col}}),
		ast.Sequence(&token.Token{Value: name, Position: &token.Position{Column: col}}, false),
	)
	return option{
		name:    name,
		node:    m,
		value:   m.Value,
		comment: comment,
	}
}()

var dataStreamOption = func() option {
	name := "data_stream.dataset"
	comment := "Dataset to write data to. Changing the dataset will send the data to a different index. You can't use `-` in the name of a dataset and only valid characters for [Elasticsearch index names](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html)."
	col := 0
	m := ast.MappingValue(&token.Token{},
		ast.String(&token.Token{Value: name, Position: &token.Position{Column: col}}),
		ast.String(&token.Token{Value: "", Position: &token.Position{Column: col}}),
	)
	return option{
		name:    name,
		node:    m,
		value:   m.Value,
		comment: comment,

		title:    "Dataset name",
		required: true,
		showUser: true,
		deflt:    getName,
	}
}()

func (p *protocolVisitor) Visit(node ast.Node) ast.Visitor {
	switch n := node.(type) {
	case *ast.SequenceNode:
		if !strings.Contains(n.Path, p.target) {
			return p
		}
		for i, c := range n.Values {
			switch c := c.(type) {
			case *ast.MappingNode:
				for _, v := range c.Values {
					key := v.Key.String()
					val := v.Value.String()
					if key == "type" {
						p.names = append(p.names, val)
						p.protocolToID[val] = i
					} else {
						if seq, ok := v.Value.(*ast.SequenceNode); ok {
							seq.IsFlowStyle = true
							for _, e := range seq.Values {
								getBaseNode(e).Comment = nil
							}
						}
						o := option{
							name:  key,
							node:  v,
							value: v.Value,
						}
						cg := v.GetComment()
						if cg != nil {
							comment := strings.ReplaceAll(cg.String(), "# ", "")
							o.comment = comment
						}
						p.protocols[i] = append(p.protocols[i], o)
					}
				}
			default:
				panic(fmt.Sprintf("unexpected type: %T", c))
			}
		}
		return nil
	default:
		return p
	}
}

func getBaseNode(n ast.Node) *ast.BaseNode {
	switch n := n.(type) {
	case *ast.AliasNode:
		return n.BaseNode
	case *ast.AnchorNode:
		return n.BaseNode
	case *ast.BoolNode:
		return n.BaseNode
	case *ast.CommentGroupNode:
		return n.BaseNode
	case *ast.CommentNode:
		return n.BaseNode
	case *ast.DirectiveNode:
		return n.BaseNode
	case *ast.DocumentNode:
		return n.BaseNode
	case *ast.FloatNode:
		return n.BaseNode
	case *ast.InfinityNode:
		return n.BaseNode
	case *ast.IntegerNode:
		return n.BaseNode
	case *ast.LiteralNode:
		return n.BaseNode
	case *ast.MappingKeyNode:
		return n.BaseNode
	case *ast.MappingNode:
		return n.BaseNode
	case *ast.MappingValueNode:
		return n.BaseNode
	case *ast.MergeKeyNode:
		return n.BaseNode
	case *ast.NanNode:
		return n.BaseNode
	case *ast.NullNode:
		return n.BaseNode
	case *ast.SequenceNode:
		return n.BaseNode
	case *ast.StringNode:
		return n.BaseNode
	case *ast.TagNode:
		return n.BaseNode
	default:
		panic(fmt.Sprintf("missed type: %T", n))
	}
}

var exclude = map[string]bool{
	"enabled": true,
	"index":   true,
}

func label(collection string) string {
	if collection == "ports" {
		return "port"
	}
	return collection
}

func elem(collection string) string {
	if collection == "ports" {
		return "p"
	}
	if strings.HasSuffix(collection, "s") {
		return strings.TrimSuffix(collection, "s")
	}
	return collection + "_elem"
}

func getName(stream string) string {
	n, ok := specialNames[stream]
	if !ok {
		return stream
	}
	return n
}

var specialNames = map[string]string{
	"memcache": "memcached",
}

func typeFor(n ast.Node) string {
	typ := n.Type()
	if typ == ast.SequenceType {
		vals := n.(*ast.SequenceNode).Values
		if len(vals) == 0 {
			// We can't know, so guess text; it's usually correct here.
			return "text"
		}
		typ = vals[0].Type()
	}
	t := strings.ToLower(typ.String())
	name, ok := typeMap[t]
	if !ok {
		return t
	}
	return name
}

var typeMap = map[string]string{
	"sequence": "text",
	"string":   "text",
	"mapping":  "yaml",
}

package core

import (
	"fmt"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/utils"
	"github.com/chainreactors/words/rule"
	"net/url"
)

type Task struct {
	baseUrl string
	depth   int
	rule    []rule.Expression
	origin  *Origin
}

func NewTaskGenerator(port string) *TaskGenerator {
	gen := &TaskGenerator{
		ports: utils.ParsePortsString(port),
		tasks: make(chan *Task),
		In:    make(chan *Task),
	}

	go func() {
		for task := range gen.In {
			gen.tasks <- task
		}
		close(gen.tasks)
	}()
	return gen

}

type TaskGenerator struct {
	Name  string
	ports []string
	tasks chan *Task
	In    chan *Task
}

func (gen *TaskGenerator) Run(baseurl string) {
	parsed, err := url.Parse(baseurl)
	if err != nil {
		logs.Log.Warnf("parse %s, %s ", baseurl, err.Error())
		return
	}

	if parsed.Scheme == "" {
		if parsed.Port() == "443" {
			parsed.Scheme = "https"
		} else {
			parsed.Scheme = "http"
		}
	}

	if len(gen.ports) == 0 {
		gen.In <- &Task{baseUrl: parsed.String()}
		return
	}

	for _, p := range gen.ports {
		if parsed.Host == "" {
			gen.In <- &Task{baseUrl: fmt.Sprintf("%s://%s:%s", parsed.Scheme, parsed.Path, p)}
		} else {
			gen.In <- &Task{baseUrl: fmt.Sprintf("%s://%s:%s/%s", parsed.Scheme, parsed.Host, p, parsed.Path)}
		}
	}
}

func (gen *TaskGenerator) Close() {
	close(gen.tasks)
}

package baseline

import (
	"fmt"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/words/rule"
	"github.com/expr-lang/expr"
	"io/ioutil"
	"testing"
)

func TestExpr(t *testing.T) {
	bl := &Baseline{
		//UrlString: "11111",
		Dir: true,
		SprayResult: &parsers.SprayResult{
			UrlString: "11111",
		},
	}
	exp, err := expr.Compile("baseline.Dir")
	fmt.Printf("%v\n", err)
	params := map[string]interface{}{
		"baseline": bl,
	}
	res, err := expr.Run(exp, params)
	fmt.Println(res, err)
}

func TestRule(t *testing.T) {
	word := "admin"
	input, _ := ioutil.ReadFile("../templates/rule/authbypass.rule")
	ss := rule.EvalWithString(string(input), word)
	for i, s := range ss {
		fmt.Printf("%d: %s\n", i, s)
	}
}

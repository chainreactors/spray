package pkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"io/ioutil"
	"strconv"
	"strings"
	"time"
)

var DefaultStatistor Statistor

func NewStatistor(url string) *Statistor {
	stat := DefaultStatistor
	stat.StartTime = time.Now().Unix()
	stat.Counts = make(map[int]int)
	stat.Sources = make(map[parsers.SpraySource]int)
	stat.BaseUrl = url
	return &stat
}

func NewStatistorFromStat(origin *Statistor) *Statistor {
	return &Statistor{
		BaseUrl:      origin.BaseUrl,
		Word:         origin.Word,
		Dictionaries: origin.Dictionaries,
		Offset:       origin.End,
		RuleFiles:    origin.RuleFiles,
		RuleFilter:   origin.RuleFilter,
		Counts:       make(map[int]int),
		Sources:      map[parsers.SpraySource]int{},
		StartTime:    time.Now().Unix(),
	}
}

type Statistor struct {
	BaseUrl        string                      `json:"url"`
	Error          string                      `json:"error"`
	Counts         map[int]int                 `json:"counts"`
	Sources        map[parsers.SpraySource]int `json:"sources"`
	FailedNumber   int32                       `json:"failed"`
	ReqTotal       int32                       `json:"req_total"`
	CheckNumber    int                         `json:"check"`
	FoundNumber    int                         `json:"found"`
	FilteredNumber int                         `json:"filtered"`
	FuzzyNumber    int                         `json:"fuzzy"`
	WafedNumber    int                         `json:"wafed"`
	End            int                         `json:"end"`
	Skipped        int                         `json:"skipped"`
	Offset         int                         `json:"offset"`
	Total          int                         `json:"total"`
	StartTime      int64                       `json:"start_time"`
	EndTime        int64                       `json:"end_time"`
	WordCount      int                         `json:"word_count"`
	Word           string                      `json:"word"`
	Dictionaries   []string                    `json:"dictionaries"`
	RuleFiles      []string                    `json:"rule_files"`
	RuleFilter     string                      `json:"rule_filter"`
}

func (stat *Statistor) ColorString() string {
	var s strings.Builder
	s.WriteString(fmt.Sprintf("[stat] %s took %d s, request total: %s, finish: %s/%s(%s skipped), found: %s, check: %s, failed: %s",
		logs.GreenLine(stat.BaseUrl),
		stat.EndTime-stat.StartTime,
		logs.YellowBold(strconv.Itoa(int(stat.ReqTotal))),
		logs.YellowBold(strconv.Itoa(stat.End)),
		logs.YellowBold(strconv.Itoa(stat.Total)),
		logs.YellowLine(strconv.Itoa(stat.Skipped)),
		logs.YellowBold(strconv.Itoa(stat.FoundNumber)),
		logs.YellowBold(strconv.Itoa(stat.CheckNumber)),
		logs.YellowBold(strconv.Itoa(int(stat.FailedNumber)))))

	if stat.FuzzyNumber != 0 {
		s.WriteString(", fuzzy: " + logs.Yellow(strconv.Itoa(stat.FuzzyNumber)))
	}
	if stat.FilteredNumber != 0 {
		s.WriteString(", filtered: " + logs.Yellow(strconv.Itoa(stat.FilteredNumber)))
	}
	if stat.WafedNumber != 0 {
		s.WriteString(", wafed: " + logs.Yellow(strconv.Itoa(stat.WafedNumber)))
	}
	return s.String()
}
func (stat *Statistor) String() string {
	var s strings.Builder
	s.WriteString(fmt.Sprintf("[stat] %s took %d s,  request total: %d, finish: %d/%d(%d skipped), found: %d, check: %d, failed: %d",
		stat.BaseUrl,
		stat.EndTime-stat.StartTime,
		stat.ReqTotal,
		stat.End,
		stat.Total,
		stat.Skipped,
		stat.FoundNumber,
		stat.CheckNumber,
		stat.FailedNumber))

	if stat.FuzzyNumber != 0 {
		s.WriteString(", fuzzy: " + strconv.Itoa(stat.FuzzyNumber))
	}
	if stat.FilteredNumber != 0 {
		s.WriteString(", filtered: " + strconv.Itoa(stat.FilteredNumber))
	}
	if stat.WafedNumber != 0 {
		s.WriteString(", wafed: " + strconv.Itoa(stat.WafedNumber))
	}
	return s.String()
}

func (stat *Statistor) CountString() string {
	if len(stat.Counts) == 0 {
		return ""
	}
	var s strings.Builder
	s.WriteString("[stat] ")
	s.WriteString(stat.BaseUrl)
	for k, v := range stat.Counts {
		if k == 0 {
			continue
		}
		s.WriteString(fmt.Sprintf(" %d: %d,", k, v))
	}
	return s.String()
}

func (stat *Statistor) SourceString() string {
	if len(stat.Sources) == 0 {
		return ""
	}
	var s strings.Builder
	s.WriteString("[stat] ")
	s.WriteString(stat.BaseUrl)
	for k, v := range stat.Sources {
		s.WriteString(fmt.Sprintf(" %s: %d,", k.Name(), v))
	}
	return s.String()
}

func (stat *Statistor) ColorCountString() string {
	if len(stat.Counts) == 0 {
		return ""
	}
	var s strings.Builder
	s.WriteString(fmt.Sprintf("[stat] %s ", stat.BaseUrl))
	for k, v := range stat.Counts {
		if k == 0 {
			continue
		}
		s.WriteString(fmt.Sprintf(" %s: %s,", logs.Cyan(strconv.Itoa(k)), logs.YellowBold(strconv.Itoa(v))))
	}
	return s.String()
}

func (stat *Statistor) ColorSourceString() string {
	if len(stat.Sources) == 0 {
		return ""
	}
	var s strings.Builder
	s.WriteString(fmt.Sprintf("[stat] %s ", stat.BaseUrl))
	for k, v := range stat.Sources {
		s.WriteString(fmt.Sprintf(" %s: %s,", logs.Cyan(k.Name()), logs.YellowBold(strconv.Itoa(v))))
	}
	return s.String()
}

func (stat *Statistor) Json() string {
	content, err := json.Marshal(stat)
	if err != nil {
		return err.Error()
	}
	return string(content) + "\n"
}

func ReadStatistors(filename string) (Statistors, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var stats Statistors
	for _, line := range bytes.Split(bytes.TrimSpace(content), []byte("\n")) {
		var stat Statistor
		err := json.Unmarshal(line, &stat)
		if err != nil {
			return nil, err
		}
		stats = append(stats, &stat)
	}

	return stats, nil
}

type Statistors []*Statistor

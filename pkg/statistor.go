package pkg

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var DefaultStatistor Statistor

func NewStatistor(url string) *Statistor {
	stat := DefaultStatistor
	stat.StartTime = time.Now().Unix()
	stat.Counts = make(map[int]int)
	stat.BaseUrl = url
	return &stat
}

type Statistor struct {
	BaseUrl        string      `json:"url"`
	Counts         map[int]int `json:"counts"`
	ReqNumber      int         `json:"req"`
	FailedNumber   int         `json:"failed"`
	CheckNumber    int         `json:"check"`
	FoundNumber    int         `json:"found"`
	FilteredNumber int         `json:"filtered"`
	FuzzyNumber    int         `json:"fuzzy"`
	WafedNumber    int         `json:"wafed"`
	End            int         `json:"end"`
	Offset         int         `json:"offset"`
	Total          int         `json:"total"`
	StartTime      int64       `json:"start_time"`
	EndTime        int64       `json:"end_time"`
	Word           string      `json:"word"`
	Dictionaries   []string    `json:"dictionaries"`
}

func (stat *Statistor) String() string {
	var s strings.Builder
	s.WriteString(fmt.Sprintf("[stat] %s took %d s, request total: %d, found: %d, check: %d, failed: %d", stat.BaseUrl, stat.EndTime-stat.StartTime, stat.ReqNumber, stat.FoundNumber, stat.CheckNumber, stat.FailedNumber))

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

func (stat *Statistor) Detail() string {
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

func (stat *Statistor) Json() string {
	content, err := json.Marshal(stat)
	if err != nil {
		return err.Error()
	}
	return string(content)
}

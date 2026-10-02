//go:build ignore

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	aegis "github.com/iconicbeen/aegis-sdks/go"
)

func main() {
	raw, _ := io.ReadAll(os.Stdin)
	var cases []string
	_ = json.Unmarshal(raw, &cases)
	out := map[string][]string{}
	for _, c := range cases {
		var ids []string
		for _, r := range aegis.Rules {
			if r.Pattern.MatchString(c) {
				ids = append(ids, r.ID)
			}
		}
		sort.Strings(ids)
		if ids == nil {
			ids = []string{}
		}
		out[c] = ids
	}
	encoded, _ := json.Marshal(out)
	fmt.Println(string(encoded))
}

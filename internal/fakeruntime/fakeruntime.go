// Package fakeruntime installs fake container runtime CLIs (docker,
// podman, and the apple container CLI) for tests. The fakes are driven by
// three files: a container state (one "<id> <label>" line per container),
// a run counter, and a calls log; they answer sb's container-runtime calls
// (ps, ls, rm, create, start, exec, info) from the state, so sb's session
// code can be tested against a runtime that behaves like the real one.
package fakeruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Files are the paths the fakes read from and write to.
type Files struct {
	// State lists the containers the runtimes "have", one "<id> <label>"
	// line per container.
	State string
	// Counter is where create takes its ids from.
	Counter string
	// Calls records one line per ps, rm, or exec call, with the arguments.
	Calls string
}

// Install writes the fake runtime binaries into binDir (docker, podman,
// container), puts binDir first on PATH, and creates the state, counter, and
// calls files as SB_FAKE_STATE, SB_FAKE_COUNTER, and SB_TEST_CALLS_LOG for
// the fakes. Set SB_FAKE_START_LIFETIME afterwards to keep a start alive
// after its stdin closes.
func Install(t testing.TB, binDir string) Files {
	t.Helper()
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	f := Files{
		State:   filepath.Join(binDir, "state"),
		Counter: filepath.Join(binDir, "counter"),
		Calls:   filepath.Join(binDir, "calls"),
	}
	for _, path := range []string{f.State, f.Counter, f.Calls} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := fakeScript
	for path, value := range map[string]string{
		"@STATE@":   f.State,
		"@COUNTER@": f.Counter,
		"@CALLS@":   f.Calls,
	} {
		script = strings.ReplaceAll(script, path, shellQuote(value))
	}
	for _, name := range []string{"docker", "podman", "container"} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SB_FAKE_STATE", f.State)
	t.Setenv("SB_FAKE_COUNTER", f.Counter)
	t.Setenv("SB_TEST_CALLS_LOG", f.Calls)
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
	return f
}

// shellQuote quotes a path for a shell double-quoted string.
func shellQuote(path string) string { return fmt.Sprintf("%q", path) }

// fakeScript is the runtime CLI the tests get: it answers sb's
// container-runtime calls from a state file, a counter, and a calls log.
// The label is the text after "label=" in sb's --filter/--label arguments
// (sb.session.id=<session id>).
const fakeScript = `#!/bin/sh
# Fake container runtime CLI for sb's tests. Driven by:
#   SB_FAKE_STATE      containers the runtime "has": "<id> <label>" lines
#   SB_FAKE_COUNTER    where create takes its ids from
#   SB_TEST_CALLS_LOG  one line per call: "<subcommand> <args joined>"
#   SB_FAKE_START_LIFETIME     while this file exists a start stays alive; without
#                            it, start lives until stdin closes
#   SB_FAKE_STALL           while this path exists the CLI never answers
#                            (a runtime that hangs: sb's deadline kills it)
#   SB_FAKE_RM_LINGER       rm -f answers without removing: the containers
#                            stay behind the call (a runtime that leaves them)
#   SB_FAKE_START_IGNORE_SIGNALS  start ignores TERM/INT and never exits by
#                            itself: the caller must kill the CLI
#   SB_FAKE_START_EXIT_CODE  the code start exits with once its wait is over
#                            (the container's exit: sb keeps it as its own)
#   SB_FAKE_CREATE_SLOW      while this path exists the creation is in
#                            flight: the call does not answer (a creation
#                            the runtime has not committed yet)
#   SB_FAKE_PIPE_CHILD      while this path exists the CLI answers, exits,
#                            and leaves a child holding its stdio (a runtime
#                            whose grandchildren keep the pipes open past
#                            the CLI's exit: sb's wait deadline bounds it)
set -eu
state=@STATE@
counter=@COUNTER@
log=@CALLS@
cmd=$1
shift
printf '%s\n' "$cmd $*" >>"$log"

# SB_FAKE_STALL: while this file exists, no call is answered. The sleeping
# loop redirects its children: an orphan holding the caller's pipes would
# keep the caller's read open after the kill.
if [ -e "${SB_FAKE_STALL:-}" ]; then
	while :; do sleep 3600 >/dev/null 2>&1; done
fi

# SB_FAKE_PIPE_CHILD: while this path exists, the CLI answers and exits
# normally but leaves a child holding its stdio behind: the caller's read
# stays open past the CLI's exit. The child dies with the path: taking the
# path away ends the loop, so no orphan outlives the test.
if [ -e "${SB_FAKE_PIPE_CHILD:-}" ]; then
	(while [ -e "${SB_FAKE_PIPE_CHILD:-}" ]; do sleep 0.05; done) &
fi

case $cmd in
info)
	# docker info, as resolveDockerHost reads it: rootful, bridge.
	echo 27.5.1
	echo '[name=seccomp,profile=builtin]'
	;;
ps)
	# ps -aq --filter <v>...: print the ids of state lines matching every
	# filter value.
	filters=""
	while [ $# -gt 0 ]; do
		case $1 in
		--filter) filters="$filters $2 ";;
		esac
		shift
	done
	while read -r id label; do
		if [ -z "$id" ]; then continue; fi
		ok=1
		for f in $filters; do
			case $f in
			id=*) [ "$id" = "${f#id=}" ] || ok=0 ;;
			label=*) [ "$label" = "${f#label=}" ] || ok=0 ;;
			*) ok=0 ;;
			esac
		done
		if [ "$ok" = 1 ] && [ -n "$filters" ]; then printf '%s\n' "$id"; fi
	done <"$state"
	;;
rm)
	# rm -f <id>...: drop the containers from the state. Mutations are
	# serialized the way the real runtime serializes them: concurrent
	# removals of disjoint labels do not lose updates.
	if [ -e "${SB_FAKE_RM_LINGER:-}" ]; then
		# Answers without removing: the containers stay behind the call,
		# and the listing after it still finds them.
		exit 0
	fi
	exec 9>>"$state.lock"
	flock 9
	for id do
		grep -v "^$id " "$state" >"$state.tmp" || true
		mv "$state.tmp" "$state"
	done
	flock -u 9
	exec 9>&-
	;;
ls)
	# ls --all --format json: the whole container list as JSON, the sb label
	# from the state.
	first=1
	out="["
	while read -r id label; do
		sid=""
		case $label in sb.session.id=*) sid="${label#sb.session.id=}" ;; esac
		if [ "$first" = 1 ]; then comma=""; else comma=","; fi
		out="$out$comma{\"id\":\"$id\",\"configuration\":{\"labels\":{\"sb.session.id\":\"$sid\"}}}"
		first=0
	done <"$state"
	printf '%s]\n' "$out"
	;;
create)
	# create <args>: register the container stopped, write the cidfile,
	# and exit: nothing runs yet — that is start's. While
	# SB_FAKE_CREATE_SLOW exists the creation is in flight: the call does
	# not answer.
	if [ -e "${SB_FAKE_CREATE_SLOW:-}" ]; then
		while [ -e "$SB_FAKE_CREATE_SLOW" ]; do sleep 0.05; done
	fi
	cidfile=""
	label=""
	while [ $# -gt 0 ]; do
		case $1 in
		--cidfile) cidfile=$2; shift 2; continue ;;
		--label) label=$2; shift 2; continue ;;
		--) shift; break ;;
		esac
		shift
	done
	if [ -s "$counter" ]; then n=$(cat "$counter"); else n=0; fi
	n=$((n+1))
	printf '%s' "$n" >"$counter"
	id="fake-container-$n"
	printf '%s\n' "$id" >"$cidfile"
	printf '%s %s\n' "$id" "$label" >>"$state"
	exit 0
	;;
start)
	# start <args>: the created container runs. The id the state knows
	# is what starts; one the state does not know starts nothing: no
	# container of that name was created.
	id=""
	for a in "$@"; do
		if grep -q "^$a " "$state"; then id=$a; break; fi
	done
	[ -n "$id" ] || exit 1
	if [ -e "${SB_FAKE_START_LIFETIME:-}" ]; then
		# Alive until the lifetime file is gone: the caller ends the
		# session at its own pace.
		while [ -e "$SB_FAKE_START_LIFETIME" ]; do sleep 0.05; done
	elif [ -n "${SB_FAKE_START_IGNORE_SIGNALS:-}" ]; then
		# Ignores TERM and INT and never exits by itself: ending the
		# run is the caller's to do, not the CLI's.
		trap '' TERM INT
		while :; do sleep 3600 >/dev/null 2>&1; done
	else
		# Alive until stdin closes: the container command ended.
		cat >/dev/null
	fi
	# The CLI's exit: the container's exit code, sb's to keep as its own.
	exit "${SB_FAKE_START_EXIT_CODE:-0}"
	;;
exec)
	# exec <args>: the container id is the first arg the state knows; the
	# rest is the container's command.
	for a in "$@"; do
		if grep -q "^$a " "$state"; then exit 0; fi
	done
	exit 1
	;;
esac
`

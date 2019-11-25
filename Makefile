.PHONY: all clean gogen mocks bazel gazelle setcap tags

BRACCEPT = bin/braccept

GAZELLE_MODE?=fix

all: tags bazel

clean:
	bazel clean
	rm -f bin/* tags
	if [ -e go/vendor ]; then rm -r go/vendor; fi

gogen:
ifndef GOGEN_SKIP
	$(MAKE) -C go/proto
else
	@echo "gogen: skipped"
endif

bazel: gogen
	rm -f bin/*
	bazel build //:scion //:scion-ci --workspace_status_command=./tools/bazel-build-env
	tar -kxf bazel-bin/scion.tar -C bin
	tar -kxf bazel-bin/scion-ci.tar -C bin

mocks:
	./tools/gomocks

gazelle:
	bazel run //:gazelle -- update -mode=$(GAZELLE_MODE) -index=false -external=external -exclude go/vendor -exclude docker/_build ./go

setcap:
	tools/setcap cap_net_admin,cap_net_raw+ep $(BRACCEPT)

tags:
	which ctags >/dev/null 2>&1 || exit 0; git ls-files c | ctags -L -

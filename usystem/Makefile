USYSTEM_PROJS:=init wserver strace devmgr singularity testsuite
UTILS_PROJS:=dmesg login memstat ping printenv

USYSTEM_PROJS+= $(patsubst %, utils/%, $(UTILS_PROJS))

USYSTEM_DFL_RULE_PROJS:=$(USYSTEM_PROJS)

USYSTEM_PROJS+=dash

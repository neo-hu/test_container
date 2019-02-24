package seccomp

import (
	"fmt"
	"github.com/neo-hu/test_container/config"
	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

var (
	actAllow = libseccomp.ActAllow
	actTrap  = libseccomp.ActTrap
	actKill  = libseccomp.ActKill
	actTrace = libseccomp.ActTrace.SetReturnCode(int16(unix.EPERM))
	actErrno = libseccomp.ActErrno.SetReturnCode(int16(unix.EPERM))
)

func InitSeccomp(cfg *config.LinuxSeccomp) error {
	if cfg == nil {
		return fmt.Errorf("cannot initialize Seccomp - nil cfg passed")
	}
	defaultAction, err := getAction(cfg.DefaultAction)
	if err != nil {
		return fmt.Errorf("error initializing seccomp - invalid default action")
	}
	filter, err := libseccomp.NewFilter(defaultAction)
	if err != nil {
		return fmt.Errorf("error creating filter: %s", err)
	}
	for _, arch := range cfg.Architectures {
		newArch, err := ConvertStringToArch(string(arch))
		if err != nil {
			return err
		}
		scmpArch, err := libseccomp.GetArchFromString(newArch)
		if err != nil {
			return fmt.Errorf("error validating Seccomp architecture: %s", err)
		}
		if err := filter.AddArch(scmpArch); err != nil {
			return fmt.Errorf("error adding architecture to seccomp filter: %s", err)
		}
	}
	if err := filter.SetNoNewPrivsBit(false); err != nil {
		return fmt.Errorf("error setting no new privileges: %s", err)
	}

	matchCall(filter, "sethostname", config.LinuxSyscall{
		Action: config.ActAllow,
	})
	for _, call := range cfg.Syscalls {
		for _, name := range call.Names {
			if err = matchCall(filter, name, call); err != nil {
				return err
			}
		}
	}
	if err = filter.Load(); err != nil {
		return fmt.Errorf("error loading seccomp filter into kernel: %s", err)
	}

	return nil
}

func matchCall(filter *libseccomp.ScmpFilter, name string, call config.LinuxSyscall) error {
	if len(name) == 0 {
		return fmt.Errorf("empty string is not a valid syscall")
	}
	callNum, err := libseccomp.GetSyscallFromName(name)
	if err != nil {
		return nil
	}
	callAct, err := getAction(call.Action)
	if err != nil {
		return fmt.Errorf("action in seccomp profile is invalid: %s", err)
	}
	if len(call.Args) == 0 {
		if err = filter.AddRule(callNum, callAct); err != nil {
			return fmt.Errorf("error adding seccomp filter rule for syscall %s: %s", name, err)
		}
	} else {
		argCounts := make([]uint, 6)
		conditions := []libseccomp.ScmpCondition{}
		for _, cond := range call.Args {
			newCond, err := getCondition(cond)
			if err != nil {
				return fmt.Errorf("error creating seccomp syscall condition for syscall %s: %s", name, err)
			}
			argCounts[cond.Index] += 1
			conditions = append(conditions, newCond)
		}
		hasMultipleArgs := false
		for _, count := range argCounts {
			if count > 1 {
				hasMultipleArgs = true
				break
			}
		}
		if hasMultipleArgs {
			for _, cond := range conditions {
				condArr := []libseccomp.ScmpCondition{cond}

				if err = filter.AddRuleConditional(callNum, callAct, condArr); err != nil {
					return fmt.Errorf("error adding seccomp rule for syscall %s: %s", name, err)
				}
			}
		} else {
			// No conditions share same argument
			// Use new, proper behavior
			if err = filter.AddRuleConditional(callNum, callAct, conditions); err != nil {
				return fmt.Errorf("error adding seccomp rule for syscall %s: %s", name, err)
			}
		}
	}
	return nil
}

func getCondition(arg config.LinuxSeccompArg) (libseccomp.ScmpCondition, error) {
	cond := libseccomp.ScmpCondition{}
	op, err := getOperator(arg.Op)
	if err != nil {
		return cond, err
	}
	return libseccomp.MakeCondition(arg.Index, op, arg.Value, arg.ValueTwo)
}

func getOperator(op config.LinuxSeccompOperator) (libseccomp.ScmpCompareOp, error) {
	switch op {
	case config.OpEqualTo:
		return libseccomp.CompareEqual, nil
	case config.OpNotEqual:
		return libseccomp.CompareNotEqual, nil
	case config.OpGreaterThan:
		return libseccomp.CompareGreater, nil
	case config.OpGreaterEqual:
		return libseccomp.CompareGreaterEqual, nil
	case config.OpLessThan:
		return libseccomp.CompareLess, nil
	case config.OpLessEqual:
		return libseccomp.CompareLessOrEqual, nil
	case config.OpMaskedEqual:
		return libseccomp.CompareMaskedEqual, nil
	default:
		return libseccomp.CompareInvalid, fmt.Errorf("invalid operator, cannot use in rule")
	}
}

var archs = map[string]string{
	"SCMP_ARCH_X86":         "x86",
	"SCMP_ARCH_X86_64":      "amd64",
	"SCMP_ARCH_X32":         "x32",
	"SCMP_ARCH_ARM":         "arm",
	"SCMP_ARCH_AARCH64":     "arm64",
	"SCMP_ARCH_MIPS":        "mips",
	"SCMP_ARCH_MIPS64":      "mips64",
	"SCMP_ARCH_MIPS64N32":   "mips64n32",
	"SCMP_ARCH_MIPSEL":      "mipsel",
	"SCMP_ARCH_MIPSEL64":    "mipsel64",
	"SCMP_ARCH_MIPSEL64N32": "mipsel64n32",
	"SCMP_ARCH_PPC":         "ppc",
	"SCMP_ARCH_PPC64":       "ppc64",
	"SCMP_ARCH_PPC64LE":     "ppc64le",
	"SCMP_ARCH_S390":        "s390",
	"SCMP_ARCH_S390X":       "s390x",
}

func ConvertStringToArch(in string) (string, error) {
	if arch, ok := archs[in]; ok == true {
		return arch, nil
	}
	return "", fmt.Errorf("string %s is not a valid arch for seccomp", in)
}

var actions = map[string]config.LinuxSeccompAction{
	"SCMP_ACT_KILL":  config.ActKill,
	"SCMP_ACT_ERRNO": config.ActErrno,
	"SCMP_ACT_TRAP":  config.ActTrap,
	"SCMP_ACT_ALLOW": config.ActAllow,
	"SCMP_ACT_TRACE": config.ActTrace,
}

func ConvertStringToAction(in string) (config.LinuxSeccompAction, error) {
	if act, ok := actions[in]; ok == true {
		return act, nil
	}
	return "", fmt.Errorf("string %s is not a valid action for seccomp", in)
}

func getAction(act config.LinuxSeccompAction) (libseccomp.ScmpAction, error) {
	switch act {
	case config.ActKill:
		return actKill, nil
	case config.ActErrno:
		return actErrno, nil
	case config.ActTrap:
		return actTrap, nil
	case config.ActAllow:
		return actAllow, nil
	case config.ActTrace:
		return actTrace, nil
	default:
		return libseccomp.ActInvalid, fmt.Errorf("invalid action, cannot use in rule")
	}
}

//var operators = map[string]config.LinuxSeccompOperator{
//	"SCMP_CMP_NE":        config.OpNotEqual,
//	"SCMP_CMP_LT":        config.OpLessThan,
//	"SCMP_CMP_LE":        config.OpLessEqual,
//	"SCMP_CMP_EQ":        config.OpEqualTo,
//	"SCMP_CMP_GE":        config.OpGreaterThanOrEqualTo,
//	"SCMP_CMP_GT":        config.OpGreaterThan,
//	"SCMP_CMP_MASKED_EQ": config.OpMaskEqualTo,
//}
//
//func ConvertStringToOperator(in string) (configs.Operator, error) {
//	if op, ok := operators[in]; ok == true {
//		return op, nil
//	}
//	return 0, fmt.Errorf("string %s is not a valid operator for seccomp", in)
//}

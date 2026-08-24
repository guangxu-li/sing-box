//go:build darwin

package pf

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

// The DIOCADDRULE ioctl number is derived from sizeof(pfiocRule), so any drift in
// these layouts does not fail a field at a time, it fails every rule load at once.
// These are the sizes xnu's pfvar.h produces on arm64 and amd64.
func TestRuleLayout(t *testing.T) {
	t.Parallel()
	require.EqualValues(t, 16, unsafe.Sizeof(Addr{}), "pf_addr")
	require.EqualValues(t, 48, unsafe.Sizeof(AddrWrap{}), "pf_addr_wrap")
	require.EqualValues(t, 64, unsafe.Sizeof(RuleAddr{}), "pf_rule_addr")
	require.EqualValues(t, 72, unsafe.Sizeof(Pool{}), "pf_pool")
	require.EqualValues(t, 88, unsafe.Sizeof(PoolAddr{}), "pf_pool_addr")
	require.EqualValues(t, 1040, unsafe.Sizeof(Rule{}), "pf_rule")
	require.EqualValues(t, 3104, unsafe.Sizeof(pfiocRule{}), "pfioc_rule")
}

// The xport union sits between the address and the negation flag; if Port and Neg
// were to overlap, a rule would silently match the wrong traffic rather than fail.
func TestRuleAddrFieldOffsets(t *testing.T) {
	t.Parallel()
	var ruleAddr RuleAddr
	require.EqualValues(t, 0, unsafe.Offsetof(ruleAddr.Addr))
	require.EqualValues(t, 48, unsafe.Offsetof(ruleAddr.Port))
	require.EqualValues(t, 52, unsafe.Offsetof(ruleAddr.PortOp))
	require.EqualValues(t, 56, unsafe.Offsetof(ruleAddr.Neg))
}

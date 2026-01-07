package cast

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUintConvertsValues(t *testing.T) {
	require.Equal(t, uint(0), Uint(0))
	require.Equal(t, uint(math.MaxInt), Uint(math.MaxInt))
	require.Equal(t, uint(42), Uint(42))
}

func TestUintPanicsOnNegativeValue(t *testing.T) {
	require.Panics(t, func() { Uint(-1) })
}

func TestInt64ConvertsValues(t *testing.T) {
	require.Equal(t, int64(0), Int64(0))
	require.Equal(t, int64(math.MaxInt), Int64(math.MaxInt))
	require.Equal(t, int64(42), Int64(42))
}

func TestInt64PanicsOnLargeValue(t *testing.T) {
	require.Panics(t, func() { Int64(uint64(math.MaxInt64 + 1)) })
}

func TestUint64ConvertsValues(t *testing.T) {
	require.Equal(t, uint64(0), Uint64(0))
	require.Equal(t, uint64(math.MaxInt), Uint64((math.MaxInt)))
	require.Equal(t, uint64(42), Uint64(42))
}

func TestUint64PanicsOnNegativeValue(t *testing.T) {
	require.Panics(t, func() { Uint64(-1) })
}

func TestInt32ConvertsValues(t *testing.T) {
	require.Equal(t, int32(0), Int32(0))
	require.Equal(t, int32(math.MaxInt32), Int32(math.MaxInt32))
	require.Equal(t, int32(42), Int32(42))
}

func TestInt32PanicsOnTooSmallValue(t *testing.T) {
	require.Panics(t, func() { Int32(int64(math.MinInt32 - 1)) })
}

func TestInt32PanicsOnLargeValue(t *testing.T) {
	require.Panics(t, func() { Int32(int64(math.MaxInt32 + 1)) })
}

func TestUint32ConvertsValues(t *testing.T) {
	require.Equal(t, uint32(0), Uint32(0))
	require.Equal(t, uint32(math.MaxUint32), Uint32(int64(math.MaxUint32)))
	require.Equal(t, uint32(42), Uint32(42))
}

func TestUint32PanicsOnNegativeValue(t *testing.T) {
	require.Panics(t, func() { Uint32(-1) })
}

func TestUint32PanicsOnLargeValue(t *testing.T) {
	require.Panics(t, func() { Uint32(int64(math.MaxUint32 + 1)) })
}

func TestUint16ConvertsValues(t *testing.T) {
	require.Equal(t, uint16(0), Uint16(0))
	require.Equal(t, uint16(math.MaxUint16), Uint16(math.MaxUint16))
	require.Equal(t, uint16(42), Uint16(42))
}

func TestUint16PanicsOnNegativeValue(t *testing.T) {
	require.Panics(t, func() { Uint16(-1) })
}

func TestUint16PanicsOnLargeValue(t *testing.T) {
	require.Panics(t, func() { Uint16(math.MaxUint16 + 1) })
}

func TestUint8ConvertsValues(t *testing.T) {
	require.Equal(t, uint8(0), Uint8(0))
	require.Equal(t, uint8(math.MaxUint8), Uint8(math.MaxUint8))
	require.Equal(t, uint8(42), Uint8(42))
}

func TestUint8PanicsOnNegativeValue(t *testing.T) {
	require.Panics(t, func() { Uint8(-1) })
}

func TestUint8PanicsOnLargeValue(t *testing.T) {
	require.Panics(t, func() { Uint8(math.MaxUint8 + 1) })
}

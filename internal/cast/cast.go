package cast

import (
	"github.com/ccoveille/go-safecast/v2"
)

type signed interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64
}

type unsigned interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}

type number interface {
	signed | unsigned
}

func SafeUint(x int) (uint, error) {
	return safecast.Convert[uint](x)
}

func Uint(x int) uint {
	u, err := SafeUint(x)
	if err != nil {
		panic(err)
	}

	return u
}

func SafeInt64[T number](x T) (int64, error) {
	return safecast.Convert[int64](x)
}

func Int64[T number](x T) int64 {
	i64, err := SafeInt64(x)
	if err != nil {
		panic(err)
	}

	return i64
}

func SafeUint64[T signed](x T) (uint64, error) {
	return safecast.Convert[uint64](x)
}

func Uint64[T signed](x T) uint64 {
	u64, err := SafeUint64(x)
	if err != nil {
		panic(err)
	}

	return u64
}

func SafeInt32[T signed](x T) (int32, error) {
	return safecast.Convert[int32](x)
}

func Int32[T signed](x T) int32 {
	i32, err := SafeInt32(x)
	if err != nil {
		panic(err)
	}

	return i32
}

func SafeUint32[T signed](x T) (uint32, error) {
	return safecast.Convert[uint32](x)
}

func Uint32[T signed](x T) uint32 {
	u32, err := SafeUint32(x)
	if err != nil {
		panic(err)
	}

	return u32
}

func SafeUint16(x int) (uint16, error) {
	return safecast.Convert[uint16](x)
}

func Uint16(x int) uint16 {
	u16, err := SafeUint16(x)
	if err != nil {
		panic(err)
	}

	return u16
}

func SafeUint8[T number](x T) (uint8, error) {
	return safecast.Convert[uint8](x)
}

func Uint8[T number](x T) uint8 {
	u8, err := SafeUint8(x)
	if err != nil {
		panic(err)
	}

	return u8
}

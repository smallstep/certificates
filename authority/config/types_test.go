package config

import (
	"reflect"
	"testing"
)

func Test_multiString_First(t *testing.T) {
	tests := []struct {
		name string
		s    multiString
		want string
	}{
		{"empty", multiString{}, ""},
		{"string", multiString{"one"}, "one"},
		{"slice", multiString{"one", "two"}, "one"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.First(); got != tt.want {
				t.Errorf("multiString.First() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_multiString_Empties(t *testing.T) {
	tests := []struct {
		name string
		s    multiString
		want bool
	}{
		{"empty", multiString{}, true},
		{"string", multiString{"one"}, false},
		{"empty string", multiString{""}, true},
		{"slice", multiString{"one", "two"}, false},
		{"empty slice", multiString{"one", ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.HasEmpties(); got != tt.want {
				t.Errorf("multiString.Empties() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_multiString_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		s       multiString
		want    []byte
		wantErr bool
	}{
		{"empty", []string{}, []byte(`""`), false},
		{"string", []string{"a string"}, []byte(`"a string"`), false},
		{"slice", []string{"string one", "string two"}, []byte(`["string one","string two"]`), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("multiString.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("multiString.MarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_multiString_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		s       *multiString
		args    args
		want    *multiString
		wantErr bool
	}{
		{"empty", new(multiString), args{[]byte{}}, new(multiString), false},
		{"empty string", new(multiString), args{[]byte(`""`)}, &multiString{""}, false},
		{"string", new(multiString), args{[]byte(`"a string"`)}, &multiString{"a string"}, false},
		{"slice", new(multiString), args{[]byte(`["string one","string two"]`)}, &multiString{"string one", "string two"}, false},
		{"error", new(multiString), args{[]byte(`["123",123]`)}, new(multiString), true},
		{"nil", nil, args{nil}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.s.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("multiString.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(tt.s, tt.want) {
				t.Errorf("multiString.UnmarshalJSON() = %v, want %v", tt.s, tt.want)
			}
		})
	}
}

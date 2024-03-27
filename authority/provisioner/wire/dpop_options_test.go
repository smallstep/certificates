package wire

import (
	"errors"
	"testing"
	"text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDPOPOptions_EvaluateTarget(t *testing.T) {
	tu := "http://wire.com:15958/clients/{{.DeviceID}}/access-token"
	target, err := template.New("DeviceID").Parse(tu)
	require.NoError(t, err)
	fail := "https:/wire.com:15958/clients/{{.DeviceId}}/access-token"
	failTarget, err := template.New("DeviceID").Parse(fail)
	require.NoError(t, err)
	type fields struct {
		target *template.Template
	}
	type args struct {
		deviceID string
	}
	tests := []struct {
		name        string
		fields      fields
		args        args
		want        string
		expectedErr error
	}{
		{
			name: "ok", fields: fields{target: target}, args: args{deviceID: "deviceID"}, want: "http://wire.com:15958/clients/deviceID/access-token",
		},
		{
			name: "fail/empty", fields: fields{target: target}, args: args{deviceID: ""}, expectedErr: errors.New("deviceID must not be empty"),
		},
		{
			name: "fail/template", fields: fields{target: failTarget}, args: args{deviceID: "bla"}, expectedErr: errors.New(`failed executing DPoP template: template: DeviceID:1:32: executing "DeviceID" at <.DeviceId>: can't evaluate field DeviceId in type struct { DeviceID string }`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &DPOPOptions{
				target: tt.fields.target,
			}
			got, err := o.EvaluateTarget(tt.args.deviceID)
			if tt.expectedErr != nil {
				assert.EqualError(t, err, tt.expectedErr.Error())
				assert.Empty(t, got)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

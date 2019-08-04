// Code generated by easyjson for marshaling/unmarshaling. DO NOT EDIT.

package types

import (
	json "encoding/json"
	container "github.com/docker/docker/api/types/container"
	mount "github.com/docker/docker/api/types/mount"
	nat "github.com/docker/go-connections/nat"
	go_units "github.com/docker/go-units"
	easyjson "github.com/mailru/easyjson"
	jlexer "github.com/mailru/easyjson/jlexer"
	jwriter "github.com/mailru/easyjson/jwriter"
	time "time"
)

// suppress unused package warning
var (
	_ *json.RawMessage
	_ *jlexer.Lexer
	_ *jwriter.Writer
	_ easyjson.Marshaler
)

func easyjson1dbef17bDecodeGithubComStackroxRoxPkgDockerTypes(in *jlexer.Lexer, out *ContainerList) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeString()
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "Id":
			out.ID = string(in.String())
		case "Labels":
			if in.IsNull() {
				in.Skip()
			} else {
				in.Delim('{')
				if !in.IsDelim('}') {
					out.Labels = make(map[string]string)
				} else {
					out.Labels = nil
				}
				for !in.IsDelim('}') {
					key := string(in.String())
					in.WantColon()
					var v1 string
					v1 = string(in.String())
					(out.Labels)[key] = v1
					in.WantComma()
				}
				in.Delim('}')
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson1dbef17bEncodeGithubComStackroxRoxPkgDockerTypes(out *jwriter.Writer, in ContainerList) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"Id\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.ID))
	}
	{
		const prefix string = ",\"Labels\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		if in.Labels == nil && (out.Flags&jwriter.NilMapAsEmpty) == 0 {
			out.RawString(`null`)
		} else {
			out.RawByte('{')
			v2First := true
			for v2Name, v2Value := range in.Labels {
				if v2First {
					v2First = false
				} else {
					out.RawByte(',')
				}
				out.String(string(v2Name))
				out.RawByte(':')
				out.String(string(v2Value))
			}
			out.RawByte('}')
		}
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v ContainerList) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson1dbef17bEncodeGithubComStackroxRoxPkgDockerTypes(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v ContainerList) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson1dbef17bEncodeGithubComStackroxRoxPkgDockerTypes(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *ContainerList) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson1dbef17bDecodeGithubComStackroxRoxPkgDockerTypes(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *ContainerList) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson1dbef17bDecodeGithubComStackroxRoxPkgDockerTypes(l, v)
}
func easyjson1dbef17bDecodeGithubComStackroxRoxPkgDockerTypes1(in *jlexer.Lexer, out *ContainerJSON) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	out.ContainerJSONBase = new(ContainerJSONBase)
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeString()
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "Mounts":
			if in.IsNull() {
				in.Skip()
				out.Mounts = nil
			} else {
				in.Delim('[')
				if out.Mounts == nil {
					if !in.IsDelim(']') {
						out.Mounts = make([]MountPoint, 0, 1)
					} else {
						out.Mounts = []MountPoint{}
					}
				} else {
					out.Mounts = (out.Mounts)[:0]
				}
				for !in.IsDelim(']') {
					var v3 MountPoint
					easyjson1dbef17bDecodeGithubComStackroxRoxPkgDockerTypes2(in, &v3)
					out.Mounts = append(out.Mounts, v3)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "Config":
			if in.IsNull() {
				in.Skip()
				out.Config = nil
			} else {
				if out.Config == nil {
					out.Config = new(Config)
				}
				easyjson1dbef17bDecodeGithubComStackroxRoxPkgDockerTypes3(in, &*out.Config)
			}
		case "NetworkSettings":
			if in.IsNull() {
				in.Skip()
				out.NetworkSettings = nil
			} else {
				if out.NetworkSettings == nil {
					out.NetworkSettings = new(NetworkSettings)
				}
				easyjson1dbef17bDecodeGithubComStackroxRoxPkgDockerTypes4(in, &*out.NetworkSettings)
			}
		case "Id":
			out.ID = string(in.String())
		case "Image":
			out.Image = string(in.String())
		case "State":
			if in.IsNull() {
				in.Skip()
				out.State = nil
			} else {
				if out.State == nil {
					out.State = new(ContainerState)
				}
				easyjson1dbef17bDecodeGithubComStackroxRoxPkgDockerTypes5(in, &*out.State)
			}
		case "Name":
			out.Name = string(in.String())
		case "AppArmorProfile":
			out.AppArmorProfile = string(in.String())
		case "HostConfig":
			if in.IsNull() {
				in.Skip()
				out.HostConfig = nil
			} else {
				if out.HostConfig == nil {
					out.HostConfig = new(HostConfig)
				}
				easyjson1dbef17bDecodeGithubComStackroxRoxPkgDockerTypes6(in, &*out.HostConfig)
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson1dbef17bEncodeGithubComStackroxRoxPkgDockerTypes1(out *jwriter.Writer, in ContainerJSON) {
	out.RawByte('{')
	first := true
	_ = first
	if len(in.Mounts) != 0 {
		const prefix string = ",\"Mounts\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('[')
			for v4, v5 := range in.Mounts {
				if v4 > 0 {
					out.RawByte(',')
				}
				easyjson1dbef17bEncodeGithubComStackroxRoxPkgDockerTypes2(out, v5)
			}
			out.RawByte(']')
		}
	}
	if in.Config != nil {
		const prefix string = ",\"Config\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		easyjson1dbef17bEncodeGithubComStackroxRoxPkgDockerTypes3(out, *in.Config)
	}
	if in.NetworkSettings != nil {
		const prefix string = ",\"NetworkSettings\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		easyjson1dbef17bEncodeGithubComStackroxRoxPkgDockerTypes4(out, *in.NetworkSettings)
	}
	{
		const prefix string = ",\"Id\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.ID))
	}
	if in.Image != "" {
		const prefix string = ",\"Image\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Image))
	}
	if in.State != nil {
		const prefix string = ",\"State\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		easyjson1dbef17bEncodeGithubComStackroxRoxPkgDockerTypes5(out, *in.State)
	}
	if in.Name != "" {
		const prefix string = ",\"Name\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Name))
	}
	if in.AppArmorProfile != "" {
		const prefix string = ",\"AppArmorProfile\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.AppArmorProfile))
	}
	if in.HostConfig != nil {
		const prefix string = ",\"HostConfig\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		easyjson1dbef17bEncodeGithubComStackroxRoxPkgDockerTypes6(out, *in.HostConfig)
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v ContainerJSON) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson1dbef17bEncodeGithubComStackroxRoxPkgDockerTypes1(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v ContainerJSON) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson1dbef17bEncodeGithubComStackroxRoxPkgDockerTypes1(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *ContainerJSON) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson1dbef17bDecodeGithubComStackroxRoxPkgDockerTypes1(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *ContainerJSON) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson1dbef17bDecodeGithubComStackroxRoxPkgDockerTypes1(l, v)
}
func easyjson1dbef17bDecodeGithubComStackroxRoxPkgDockerTypes6(in *jlexer.Lexer, out *HostConfig) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeString()
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "CapAdd":
			if data := in.Raw(); in.Ok() {
				in.AddError((out.CapAdd).UnmarshalJSON(data))
			}
		case "CapDrop":
			if data := in.Raw(); in.Ok() {
				in.AddError((out.CapDrop).UnmarshalJSON(data))
			}
		case "SecurityOpt":
			if in.IsNull() {
				in.Skip()
				out.SecurityOpt = nil
			} else {
				in.Delim('[')
				if out.SecurityOpt == nil {
					if !in.IsDelim(']') {
						out.SecurityOpt = make([]string, 0, 4)
					} else {
						out.SecurityOpt = []string{}
					}
				} else {
					out.SecurityOpt = (out.SecurityOpt)[:0]
				}
				for !in.IsDelim(']') {
					var v6 string
					v6 = string(in.String())
					out.SecurityOpt = append(out.SecurityOpt, v6)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "NetworkMode":
			out.NetworkMode = container.NetworkMode(in.String())
		case "RestartPolicy":
			easyjson1dbef17bDecodeGithubComDockerDockerApiTypesContainer(in, &out.RestartPolicy)
		case "IpcMode":
			out.IpcMode = container.IpcMode(in.String())
		case "PidMode":
			out.PidMode = container.PidMode(in.String())
		case "Privileged":
			out.Privileged = bool(in.Bool())
		case "ReadonlyRootfs":
			out.ReadonlyRootfs = bool(in.Bool())
		case "UTSMode":
			out.UTSMode = container.UTSMode(in.String())
		case "UsernsMode":
			out.UsernsMode = container.UsernsMode(in.String())
		case "CgroupParent":
			out.CgroupParent = string(in.String())
		case "CpuShares":
			out.CPUShares = int64(in.Int64())
		case "Memory":
			out.Memory = int64(in.Int64())
		case "Devices":
			if in.IsNull() {
				in.Skip()
				out.Devices = nil
			} else {
				in.Delim('[')
				if out.Devices == nil {
					if !in.IsDelim(']') {
						out.Devices = make([]container.DeviceMapping, 0, 1)
					} else {
						out.Devices = []container.DeviceMapping{}
					}
				} else {
					out.Devices = (out.Devices)[:0]
				}
				for !in.IsDelim(']') {
					var v7 container.DeviceMapping
					easyjson1dbef17bDecodeGithubComDockerDockerApiTypesContainer1(in, &v7)
					out.Devices = append(out.Devices, v7)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "PidsLimit":
			out.PidsLimit = int64(in.Int64())
		case "Ulimits":
			if in.IsNull() {
				in.Skip()
				out.Ulimits = nil
			} else {
				in.Delim('[')
				if out.Ulimits == nil {
					if !in.IsDelim(']') {
						out.Ulimits = make([]*go_units.Ulimit, 0, 8)
					} else {
						out.Ulimits = []*go_units.Ulimit{}
					}
				} else {
					out.Ulimits = (out.Ulimits)[:0]
				}
				for !in.IsDelim(']') {
					var v8 *go_units.Ulimit
					if in.IsNull() {
						in.Skip()
						v8 = nil
					} else {
						if v8 == nil {
							v8 = new(go_units.Ulimit)
						}
						easyjson1dbef17bDecodeGithubComDockerGoUnits(in, &*v8)
					}
					out.Ulimits = append(out.Ulimits, v8)
					in.WantComma()
				}
				in.Delim(']')
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson1dbef17bEncodeGithubComStackroxRoxPkgDockerTypes6(out *jwriter.Writer, in HostConfig) {
	out.RawByte('{')
	first := true
	_ = first
	if len(in.CapAdd) != 0 {
		const prefix string = ",\"CapAdd\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('[')
			for v9, v10 := range in.CapAdd {
				if v9 > 0 {
					out.RawByte(',')
				}
				out.String(string(v10))
			}
			out.RawByte(']')
		}
	}
	if len(in.CapDrop) != 0 {
		const prefix string = ",\"CapDrop\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('[')
			for v11, v12 := range in.CapDrop {
				if v11 > 0 {
					out.RawByte(',')
				}
				out.String(string(v12))
			}
			out.RawByte(']')
		}
	}
	if len(in.SecurityOpt) != 0 {
		const prefix string = ",\"SecurityOpt\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('[')
			for v13, v14 := range in.SecurityOpt {
				if v13 > 0 {
					out.RawByte(',')
				}
				out.String(string(v14))
			}
			out.RawByte(']')
		}
	}
	if in.NetworkMode != "" {
		const prefix string = ",\"NetworkMode\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.NetworkMode))
	}
	if true {
		const prefix string = ",\"RestartPolicy\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		easyjson1dbef17bEncodeGithubComDockerDockerApiTypesContainer(out, in.RestartPolicy)
	}
	if in.IpcMode != "" {
		const prefix string = ",\"IpcMode\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.IpcMode))
	}
	if in.PidMode != "" {
		const prefix string = ",\"PidMode\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.PidMode))
	}
	if in.Privileged {
		const prefix string = ",\"Privileged\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Bool(bool(in.Privileged))
	}
	if in.ReadonlyRootfs {
		const prefix string = ",\"ReadonlyRootfs\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Bool(bool(in.ReadonlyRootfs))
	}
	if in.UTSMode != "" {
		const prefix string = ",\"UTSMode\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.UTSMode))
	}
	if in.UsernsMode != "" {
		const prefix string = ",\"UsernsMode\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.UsernsMode))
	}
	if in.CgroupParent != "" {
		const prefix string = ",\"CgroupParent\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.CgroupParent))
	}
	{
		const prefix string = ",\"CpuShares\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int64(int64(in.CPUShares))
	}
	if in.Memory != 0 {
		const prefix string = ",\"Memory\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int64(int64(in.Memory))
	}
	if len(in.Devices) != 0 {
		const prefix string = ",\"Devices\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('[')
			for v15, v16 := range in.Devices {
				if v15 > 0 {
					out.RawByte(',')
				}
				easyjson1dbef17bEncodeGithubComDockerDockerApiTypesContainer1(out, v16)
			}
			out.RawByte(']')
		}
	}
	if in.PidsLimit != 0 {
		const prefix string = ",\"PidsLimit\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int64(int64(in.PidsLimit))
	}
	if len(in.Ulimits) != 0 {
		const prefix string = ",\"Ulimits\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('[')
			for v17, v18 := range in.Ulimits {
				if v17 > 0 {
					out.RawByte(',')
				}
				if v18 == nil {
					out.RawString("null")
				} else {
					easyjson1dbef17bEncodeGithubComDockerGoUnits(out, *v18)
				}
			}
			out.RawByte(']')
		}
	}
	out.RawByte('}')
}
func easyjson1dbef17bDecodeGithubComDockerGoUnits(in *jlexer.Lexer, out *go_units.Ulimit) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeString()
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "Name":
			out.Name = string(in.String())
		case "Hard":
			out.Hard = int64(in.Int64())
		case "Soft":
			out.Soft = int64(in.Int64())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson1dbef17bEncodeGithubComDockerGoUnits(out *jwriter.Writer, in go_units.Ulimit) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"Name\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Name))
	}
	{
		const prefix string = ",\"Hard\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int64(int64(in.Hard))
	}
	{
		const prefix string = ",\"Soft\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int64(int64(in.Soft))
	}
	out.RawByte('}')
}
func easyjson1dbef17bDecodeGithubComDockerDockerApiTypesContainer1(in *jlexer.Lexer, out *container.DeviceMapping) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeString()
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "PathOnHost":
			out.PathOnHost = string(in.String())
		case "PathInContainer":
			out.PathInContainer = string(in.String())
		case "CgroupPermissions":
			out.CgroupPermissions = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson1dbef17bEncodeGithubComDockerDockerApiTypesContainer1(out *jwriter.Writer, in container.DeviceMapping) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"PathOnHost\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.PathOnHost))
	}
	{
		const prefix string = ",\"PathInContainer\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.PathInContainer))
	}
	{
		const prefix string = ",\"CgroupPermissions\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.CgroupPermissions))
	}
	out.RawByte('}')
}
func easyjson1dbef17bDecodeGithubComDockerDockerApiTypesContainer(in *jlexer.Lexer, out *container.RestartPolicy) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeString()
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "Name":
			out.Name = string(in.String())
		case "MaximumRetryCount":
			out.MaximumRetryCount = int(in.Int())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson1dbef17bEncodeGithubComDockerDockerApiTypesContainer(out *jwriter.Writer, in container.RestartPolicy) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"Name\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Name))
	}
	{
		const prefix string = ",\"MaximumRetryCount\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int(int(in.MaximumRetryCount))
	}
	out.RawByte('}')
}
func easyjson1dbef17bDecodeGithubComStackroxRoxPkgDockerTypes5(in *jlexer.Lexer, out *ContainerState) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeString()
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "Running":
			out.Running = bool(in.Bool())
		case "Health":
			if in.IsNull() {
				in.Skip()
				out.Health = nil
			} else {
				if out.Health == nil {
					out.Health = new(Health)
				}
				easyjson1dbef17bDecodeGithubComStackroxRoxPkgDockerTypes7(in, &*out.Health)
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson1dbef17bEncodeGithubComStackroxRoxPkgDockerTypes5(out *jwriter.Writer, in ContainerState) {
	out.RawByte('{')
	first := true
	_ = first
	if in.Running {
		const prefix string = ",\"Running\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Bool(bool(in.Running))
	}
	if in.Health != nil {
		const prefix string = ",\"Health\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		easyjson1dbef17bEncodeGithubComStackroxRoxPkgDockerTypes7(out, *in.Health)
	}
	out.RawByte('}')
}
func easyjson1dbef17bDecodeGithubComStackroxRoxPkgDockerTypes7(in *jlexer.Lexer, out *Health) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeString()
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "Status":
			out.Status = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson1dbef17bEncodeGithubComStackroxRoxPkgDockerTypes7(out *jwriter.Writer, in Health) {
	out.RawByte('{')
	first := true
	_ = first
	if in.Status != "" {
		const prefix string = ",\"Status\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Status))
	}
	out.RawByte('}')
}
func easyjson1dbef17bDecodeGithubComStackroxRoxPkgDockerTypes4(in *jlexer.Lexer, out *NetworkSettings) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeString()
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "Networks":
			if in.IsNull() {
				in.Skip()
			} else {
				in.Delim('{')
				if !in.IsDelim('}') {
					out.Networks = make(map[string]struct{})
				} else {
					out.Networks = nil
				}
				for !in.IsDelim('}') {
					key := string(in.String())
					in.WantColon()
					var v19 struct{}
					easyjson1dbef17bDecode(in, &v19)
					(out.Networks)[key] = v19
					in.WantComma()
				}
				in.Delim('}')
			}
		case "Ports":
			if in.IsNull() {
				in.Skip()
			} else {
				in.Delim('{')
				if !in.IsDelim('}') {
					out.Ports = make(nat.PortMap)
				} else {
					out.Ports = nil
				}
				for !in.IsDelim('}') {
					key := nat.Port(in.String())
					in.WantColon()
					var v20 []nat.PortBinding
					if in.IsNull() {
						in.Skip()
						v20 = nil
					} else {
						in.Delim('[')
						if v20 == nil {
							if !in.IsDelim(']') {
								v20 = make([]nat.PortBinding, 0, 2)
							} else {
								v20 = []nat.PortBinding{}
							}
						} else {
							v20 = (v20)[:0]
						}
						for !in.IsDelim(']') {
							var v21 nat.PortBinding
							easyjson1dbef17bDecodeGithubComDockerGoConnectionsNat(in, &v21)
							v20 = append(v20, v21)
							in.WantComma()
						}
						in.Delim(']')
					}
					(out.Ports)[key] = v20
					in.WantComma()
				}
				in.Delim('}')
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson1dbef17bEncodeGithubComStackroxRoxPkgDockerTypes4(out *jwriter.Writer, in NetworkSettings) {
	out.RawByte('{')
	first := true
	_ = first
	if len(in.Networks) != 0 {
		const prefix string = ",\"Networks\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('{')
			v22First := true
			for v22Name, v22Value := range in.Networks {
				if v22First {
					v22First = false
				} else {
					out.RawByte(',')
				}
				out.String(string(v22Name))
				out.RawByte(':')
				easyjson1dbef17bEncode(out, v22Value)
			}
			out.RawByte('}')
		}
	}
	if len(in.Ports) != 0 {
		const prefix string = ",\"Ports\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('{')
			v23First := true
			for v23Name, v23Value := range in.Ports {
				if v23First {
					v23First = false
				} else {
					out.RawByte(',')
				}
				out.String(string(v23Name))
				out.RawByte(':')
				if v23Value == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
					out.RawString("null")
				} else {
					out.RawByte('[')
					for v24, v25 := range v23Value {
						if v24 > 0 {
							out.RawByte(',')
						}
						easyjson1dbef17bEncodeGithubComDockerGoConnectionsNat(out, v25)
					}
					out.RawByte(']')
				}
			}
			out.RawByte('}')
		}
	}
	out.RawByte('}')
}
func easyjson1dbef17bDecodeGithubComDockerGoConnectionsNat(in *jlexer.Lexer, out *nat.PortBinding) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeString()
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "HostIp":
			out.HostIP = string(in.String())
		case "HostPort":
			out.HostPort = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson1dbef17bEncodeGithubComDockerGoConnectionsNat(out *jwriter.Writer, in nat.PortBinding) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"HostIp\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.HostIP))
	}
	{
		const prefix string = ",\"HostPort\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.HostPort))
	}
	out.RawByte('}')
}
func easyjson1dbef17bDecode(in *jlexer.Lexer, out *struct{}) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeString()
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson1dbef17bEncode(out *jwriter.Writer, in struct{}) {
	out.RawByte('{')
	first := true
	_ = first
	out.RawByte('}')
}
func easyjson1dbef17bDecodeGithubComStackroxRoxPkgDockerTypes3(in *jlexer.Lexer, out *Config) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeString()
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "Healthcheck":
			if in.IsNull() {
				in.Skip()
				out.Healthcheck = nil
			} else {
				if out.Healthcheck == nil {
					out.Healthcheck = new(container.HealthConfig)
				}
				easyjson1dbef17bDecodeGithubComDockerDockerApiTypesContainer2(in, &*out.Healthcheck)
			}
		case "User":
			out.User = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson1dbef17bEncodeGithubComStackroxRoxPkgDockerTypes3(out *jwriter.Writer, in Config) {
	out.RawByte('{')
	first := true
	_ = first
	if in.Healthcheck != nil {
		const prefix string = ",\"Healthcheck\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		easyjson1dbef17bEncodeGithubComDockerDockerApiTypesContainer2(out, *in.Healthcheck)
	}
	if in.User != "" {
		const prefix string = ",\"User\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.User))
	}
	out.RawByte('}')
}
func easyjson1dbef17bDecodeGithubComDockerDockerApiTypesContainer2(in *jlexer.Lexer, out *container.HealthConfig) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeString()
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "Test":
			if in.IsNull() {
				in.Skip()
				out.Test = nil
			} else {
				in.Delim('[')
				if out.Test == nil {
					if !in.IsDelim(']') {
						out.Test = make([]string, 0, 4)
					} else {
						out.Test = []string{}
					}
				} else {
					out.Test = (out.Test)[:0]
				}
				for !in.IsDelim(']') {
					var v26 string
					v26 = string(in.String())
					out.Test = append(out.Test, v26)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "Interval":
			out.Interval = time.Duration(in.Int64())
		case "Timeout":
			out.Timeout = time.Duration(in.Int64())
		case "StartPeriod":
			out.StartPeriod = time.Duration(in.Int64())
		case "Retries":
			out.Retries = int(in.Int())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson1dbef17bEncodeGithubComDockerDockerApiTypesContainer2(out *jwriter.Writer, in container.HealthConfig) {
	out.RawByte('{')
	first := true
	_ = first
	if len(in.Test) != 0 {
		const prefix string = ",\"Test\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('[')
			for v27, v28 := range in.Test {
				if v27 > 0 {
					out.RawByte(',')
				}
				out.String(string(v28))
			}
			out.RawByte(']')
		}
	}
	if in.Interval != 0 {
		const prefix string = ",\"Interval\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int64(int64(in.Interval))
	}
	if in.Timeout != 0 {
		const prefix string = ",\"Timeout\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int64(int64(in.Timeout))
	}
	if in.StartPeriod != 0 {
		const prefix string = ",\"StartPeriod\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int64(int64(in.StartPeriod))
	}
	if in.Retries != 0 {
		const prefix string = ",\"Retries\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int(int(in.Retries))
	}
	out.RawByte('}')
}
func easyjson1dbef17bDecodeGithubComStackroxRoxPkgDockerTypes2(in *jlexer.Lexer, out *MountPoint) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeString()
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "Type":
			out.Type = mount.Type(in.String())
		case "Name":
			out.Name = string(in.String())
		case "Source":
			out.Source = string(in.String())
		case "Destination":
			out.Destination = string(in.String())
		case "Driver":
			out.Driver = string(in.String())
		case "Mode":
			out.Mode = string(in.String())
		case "Propagation":
			out.Propagation = mount.Propagation(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson1dbef17bEncodeGithubComStackroxRoxPkgDockerTypes2(out *jwriter.Writer, in MountPoint) {
	out.RawByte('{')
	first := true
	_ = first
	if in.Type != "" {
		const prefix string = ",\"Type\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Type))
	}
	if in.Name != "" {
		const prefix string = ",\"Name\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Name))
	}
	if in.Source != "" {
		const prefix string = ",\"Source\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Source))
	}
	if in.Destination != "" {
		const prefix string = ",\"Destination\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Destination))
	}
	if in.Driver != "" {
		const prefix string = ",\"Driver\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Driver))
	}
	if in.Mode != "" {
		const prefix string = ",\"Mode\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Mode))
	}
	if in.Propagation != "" {
		const prefix string = ",\"Propagation\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Propagation))
	}
	out.RawByte('}')
}
//lint:file-ignore SA4006 This is a generated file

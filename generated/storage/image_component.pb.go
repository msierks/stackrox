// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: storage/image_component.proto

package storage

import (
	encoding_binary "encoding/binary"
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/golang/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type ImageComponent struct {
	Id        string     `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty" search:"Component ID,store" sql:"pk"`
	Name      string     `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty" search:"Component,store"`
	Version   string     `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty" search:"Component Version,store"`
	License   *License   `protobuf:"bytes,4,opt,name=license,proto3" json:"license,omitempty"`
	Priority  int64      `protobuf:"varint,5,opt,name=priority,proto3" json:"priority,omitempty"`
	Source    SourceType `protobuf:"varint,6,opt,name=source,proto3,enum=storage.SourceType" json:"source,omitempty" search:"Component Source,store"`
	RiskScore float32    `protobuf:"fixed32,7,opt,name=risk_score,json=riskScore,proto3" json:"risk_score,omitempty" search:"Risk Score,hidden"`
	// Types that are valid to be assigned to SetTopCvss:
	//	*ImageComponent_TopCvss
	SetTopCvss isImageComponent_SetTopCvss `protobuf_oneof:"set_top_cvss"`
	// Component version that fixes all the fixable vulnerabilities in this component.
	FixedBy              string   `protobuf:"bytes,9,opt,name=fixed_by,json=fixedBy,proto3" json:"fixed_by,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ImageComponent) Reset()         { *m = ImageComponent{} }
func (m *ImageComponent) String() string { return proto.CompactTextString(m) }
func (*ImageComponent) ProtoMessage()    {}
func (*ImageComponent) Descriptor() ([]byte, []int) {
	return fileDescriptor_f72cea254a8774ea, []int{0}
}
func (m *ImageComponent) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ImageComponent) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ImageComponent.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *ImageComponent) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ImageComponent.Merge(m, src)
}
func (m *ImageComponent) XXX_Size() int {
	return m.Size()
}
func (m *ImageComponent) XXX_DiscardUnknown() {
	xxx_messageInfo_ImageComponent.DiscardUnknown(m)
}

var xxx_messageInfo_ImageComponent proto.InternalMessageInfo

type isImageComponent_SetTopCvss interface {
	isImageComponent_SetTopCvss()
	MarshalTo([]byte) (int, error)
	Size() int
	Clone() isImageComponent_SetTopCvss
}

type ImageComponent_TopCvss struct {
	TopCvss float32 `protobuf:"fixed32,8,opt,name=top_cvss,json=topCvss,proto3,oneof" json:"top_cvss,omitempty" search:"Component Top CVSS,store"`
}

func (*ImageComponent_TopCvss) isImageComponent_SetTopCvss() {}
func (m *ImageComponent_TopCvss) Clone() isImageComponent_SetTopCvss {
	if m == nil {
		return nil
	}
	cloned := new(ImageComponent_TopCvss)
	*cloned = *m

	return cloned
}

func (m *ImageComponent) GetSetTopCvss() isImageComponent_SetTopCvss {
	if m != nil {
		return m.SetTopCvss
	}
	return nil
}

func (m *ImageComponent) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *ImageComponent) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *ImageComponent) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

func (m *ImageComponent) GetLicense() *License {
	if m != nil {
		return m.License
	}
	return nil
}

func (m *ImageComponent) GetPriority() int64 {
	if m != nil {
		return m.Priority
	}
	return 0
}

func (m *ImageComponent) GetSource() SourceType {
	if m != nil {
		return m.Source
	}
	return SourceType_OS
}

func (m *ImageComponent) GetRiskScore() float32 {
	if m != nil {
		return m.RiskScore
	}
	return 0
}

func (m *ImageComponent) GetTopCvss() float32 {
	if x, ok := m.GetSetTopCvss().(*ImageComponent_TopCvss); ok {
		return x.TopCvss
	}
	return 0
}

func (m *ImageComponent) GetFixedBy() string {
	if m != nil {
		return m.FixedBy
	}
	return ""
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*ImageComponent) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*ImageComponent_TopCvss)(nil),
	}
}

func (m *ImageComponent) MessageClone() proto.Message {
	return m.Clone()
}
func (m *ImageComponent) Clone() *ImageComponent {
	if m == nil {
		return nil
	}
	cloned := new(ImageComponent)
	*cloned = *m

	cloned.License = m.License.Clone()
	if m.SetTopCvss != nil {
		cloned.SetTopCvss = m.SetTopCvss.Clone()
	}
	return cloned
}

type ComponentCVEEdge struct {
	// base 64 encoded Component:CVE ids.
	Id        string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	IsFixable bool   `protobuf:"varint,2,opt,name=is_fixable,json=isFixable,proto3" json:"is_fixable,omitempty" search:"Fixable,store"`
	// Whether there is a version the CVE is fixed in the component.
	//
	// Types that are valid to be assigned to HasFixedBy:
	//	*ComponentCVEEdge_FixedBy
	HasFixedBy           isComponentCVEEdge_HasFixedBy `protobuf_oneof:"has_fixed_by"`
	XXX_NoUnkeyedLiteral struct{}                      `json:"-"`
	XXX_unrecognized     []byte                        `json:"-"`
	XXX_sizecache        int32                         `json:"-"`
}

func (m *ComponentCVEEdge) Reset()         { *m = ComponentCVEEdge{} }
func (m *ComponentCVEEdge) String() string { return proto.CompactTextString(m) }
func (*ComponentCVEEdge) ProtoMessage()    {}
func (*ComponentCVEEdge) Descriptor() ([]byte, []int) {
	return fileDescriptor_f72cea254a8774ea, []int{1}
}
func (m *ComponentCVEEdge) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ComponentCVEEdge) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ComponentCVEEdge.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *ComponentCVEEdge) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ComponentCVEEdge.Merge(m, src)
}
func (m *ComponentCVEEdge) XXX_Size() int {
	return m.Size()
}
func (m *ComponentCVEEdge) XXX_DiscardUnknown() {
	xxx_messageInfo_ComponentCVEEdge.DiscardUnknown(m)
}

var xxx_messageInfo_ComponentCVEEdge proto.InternalMessageInfo

type isComponentCVEEdge_HasFixedBy interface {
	isComponentCVEEdge_HasFixedBy()
	MarshalTo([]byte) (int, error)
	Size() int
	Clone() isComponentCVEEdge_HasFixedBy
}

type ComponentCVEEdge_FixedBy struct {
	FixedBy string `protobuf:"bytes,3,opt,name=fixed_by,json=fixedBy,proto3,oneof" json:"fixed_by,omitempty" search:"Fixed By,store,hidden"`
}

func (*ComponentCVEEdge_FixedBy) isComponentCVEEdge_HasFixedBy() {}
func (m *ComponentCVEEdge_FixedBy) Clone() isComponentCVEEdge_HasFixedBy {
	if m == nil {
		return nil
	}
	cloned := new(ComponentCVEEdge_FixedBy)
	*cloned = *m

	return cloned
}

func (m *ComponentCVEEdge) GetHasFixedBy() isComponentCVEEdge_HasFixedBy {
	if m != nil {
		return m.HasFixedBy
	}
	return nil
}

func (m *ComponentCVEEdge) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *ComponentCVEEdge) GetIsFixable() bool {
	if m != nil {
		return m.IsFixable
	}
	return false
}

func (m *ComponentCVEEdge) GetFixedBy() string {
	if x, ok := m.GetHasFixedBy().(*ComponentCVEEdge_FixedBy); ok {
		return x.FixedBy
	}
	return ""
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*ComponentCVEEdge) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*ComponentCVEEdge_FixedBy)(nil),
	}
}

func (m *ComponentCVEEdge) MessageClone() proto.Message {
	return m.Clone()
}
func (m *ComponentCVEEdge) Clone() *ComponentCVEEdge {
	if m == nil {
		return nil
	}
	cloned := new(ComponentCVEEdge)
	*cloned = *m

	if m.HasFixedBy != nil {
		cloned.HasFixedBy = m.HasFixedBy.Clone()
	}
	return cloned
}

type ComponentCVEEdgeEntry struct {
	ComponentId          string            `protobuf:"bytes,1,opt,name=component_id,json=componentId,proto3" json:"component_id,omitempty" search:"Component ID" sql:"pk"`
	CveId                string            `protobuf:"bytes,2,opt,name=cve_id,json=cveId,proto3" json:"cve_id,omitempty" search:"CVE" sql:"pk"`
	Edge                 *ComponentCVEEdge `protobuf:"bytes,3,opt,name=edge,proto3" json:"edge,omitempty"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *ComponentCVEEdgeEntry) Reset()         { *m = ComponentCVEEdgeEntry{} }
func (m *ComponentCVEEdgeEntry) String() string { return proto.CompactTextString(m) }
func (*ComponentCVEEdgeEntry) ProtoMessage()    {}
func (*ComponentCVEEdgeEntry) Descriptor() ([]byte, []int) {
	return fileDescriptor_f72cea254a8774ea, []int{2}
}
func (m *ComponentCVEEdgeEntry) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ComponentCVEEdgeEntry) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ComponentCVEEdgeEntry.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *ComponentCVEEdgeEntry) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ComponentCVEEdgeEntry.Merge(m, src)
}
func (m *ComponentCVEEdgeEntry) XXX_Size() int {
	return m.Size()
}
func (m *ComponentCVEEdgeEntry) XXX_DiscardUnknown() {
	xxx_messageInfo_ComponentCVEEdgeEntry.DiscardUnknown(m)
}

var xxx_messageInfo_ComponentCVEEdgeEntry proto.InternalMessageInfo

func (m *ComponentCVEEdgeEntry) GetComponentId() string {
	if m != nil {
		return m.ComponentId
	}
	return ""
}

func (m *ComponentCVEEdgeEntry) GetCveId() string {
	if m != nil {
		return m.CveId
	}
	return ""
}

func (m *ComponentCVEEdgeEntry) GetEdge() *ComponentCVEEdge {
	if m != nil {
		return m.Edge
	}
	return nil
}

func (m *ComponentCVEEdgeEntry) MessageClone() proto.Message {
	return m.Clone()
}
func (m *ComponentCVEEdgeEntry) Clone() *ComponentCVEEdgeEntry {
	if m == nil {
		return nil
	}
	cloned := new(ComponentCVEEdgeEntry)
	*cloned = *m

	cloned.Edge = m.Edge.Clone()
	return cloned
}

func init() {
	proto.RegisterType((*ImageComponent)(nil), "storage.ImageComponent")
	proto.RegisterType((*ComponentCVEEdge)(nil), "storage.ComponentCVEEdge")
	proto.RegisterType((*ComponentCVEEdgeEntry)(nil), "storage.ComponentCVEEdgeEntry")
}

func init() { proto.RegisterFile("storage/image_component.proto", fileDescriptor_f72cea254a8774ea) }

var fileDescriptor_f72cea254a8774ea = []byte{
	// 588 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x64, 0x53, 0xd1, 0x6e, 0xd3, 0x3c,
	0x18, 0x5d, 0xba, 0xae, 0x69, 0xbd, 0xa9, 0x9a, 0xbc, 0x7f, 0xbf, 0xd2, 0x0a, 0x92, 0x10, 0x86,
	0x14, 0xa1, 0xd1, 0xa1, 0xc1, 0x05, 0x4c, 0x02, 0xa4, 0x94, 0x22, 0x2a, 0x71, 0x81, 0xd2, 0xa9,
	0x17, 0xdc, 0x44, 0x69, 0xe2, 0xa5, 0x56, 0xdb, 0x38, 0xc4, 0xa1, 0x6a, 0xee, 0x79, 0x08, 0x9e,
	0x82, 0x57, 0xe0, 0x96, 0x4b, 0x9e, 0x20, 0x42, 0xe5, 0x0d, 0xf2, 0x04, 0x28, 0x76, 0x1c, 0xb2,
	0xf5, 0xce, 0xfe, 0xbe, 0x73, 0xce, 0x77, 0x6c, 0x1f, 0x83, 0xfb, 0x34, 0x21, 0xb1, 0x1b, 0xa0,
	0x0b, 0xbc, 0x72, 0x03, 0xe4, 0x78, 0x64, 0x15, 0x91, 0x10, 0x85, 0xc9, 0x20, 0x8a, 0x49, 0x42,
	0xa0, 0x5c, 0xb6, 0xfb, 0x27, 0xb7, 0x70, 0xbc, 0xdb, 0xff, 0x2f, 0x20, 0x01, 0x61, 0xcb, 0x8b,
	0x62, 0xc5, 0xab, 0xc6, 0xd7, 0x26, 0xe8, 0x8e, 0x0b, 0xd4, 0x50, 0x88, 0xc1, 0x17, 0xa0, 0x81,
	0x7d, 0x45, 0xd2, 0x25, 0xb3, 0x63, 0x99, 0x79, 0xa6, 0x9d, 0x51, 0xe4, 0xc6, 0xde, 0xfc, 0xca,
	0xa8, 0x20, 0xfa, 0xf8, 0xed, 0x79, 0x31, 0x02, 0x19, 0x3a, 0xfd, 0xbc, 0xbc, 0x32, 0xa2, 0x85,
	0x61, 0x37, 0xb0, 0x0f, 0x9f, 0x82, 0x66, 0xe8, 0xae, 0x90, 0xd2, 0x60, 0xdc, 0x7b, 0x79, 0xa6,
	0x29, 0x3b, 0xdc, 0x92, 0x68, 0x33, 0x24, 0x7c, 0x0d, 0xe4, 0x35, 0x8a, 0x29, 0x26, 0xa1, 0xb2,
	0xcf, 0x48, 0x67, 0x79, 0xa6, 0xe9, 0xbb, 0x03, 0xa7, 0x1c, 0x24, 0xc8, 0x82, 0x04, 0x1f, 0x03,
	0x79, 0x89, 0x3d, 0x14, 0x52, 0xa4, 0x34, 0x75, 0xc9, 0x3c, 0xbc, 0x3c, 0x1e, 0x94, 0x67, 0x1f,
	0x7c, 0xe0, 0x75, 0x5b, 0x00, 0x60, 0x1f, 0xb4, 0xa3, 0x18, 0x93, 0x18, 0x27, 0xa9, 0x72, 0xa0,
	0x4b, 0xe6, 0xbe, 0x5d, 0xed, 0xe1, 0x47, 0xd0, 0xa2, 0xe4, 0x4b, 0xec, 0x21, 0xa5, 0xa5, 0x4b,
	0x66, 0xf7, 0xf2, 0xa4, 0x92, 0x99, 0xb0, 0xf2, 0x75, 0x1a, 0x21, 0xeb, 0x61, 0x9e, 0x69, 0xda,
	0xae, 0x37, 0x8e, 0x10, 0xd6, 0x4a, 0x1d, 0xf8, 0x0a, 0x80, 0x18, 0xd3, 0x85, 0x43, 0x3d, 0x12,
	0x23, 0x45, 0xd6, 0x25, 0xb3, 0x61, 0xa9, 0x79, 0xa6, 0xf5, 0x85, 0x80, 0x8d, 0xe9, 0x42, 0x9f,
	0x14, 0xdd, 0xf3, 0x39, 0xf6, 0x7d, 0x14, 0x1a, 0x76, 0xa7, 0x60, 0xb0, 0x12, 0xb4, 0x40, 0x3b,
	0x21, 0x91, 0xe3, 0xad, 0x29, 0x55, 0xda, 0x8c, 0xfc, 0x28, 0xcf, 0xb4, 0x07, 0xbb, 0xd3, 0xaf,
	0x49, 0xa4, 0x0f, 0xa7, 0x93, 0x49, 0x39, 0xff, 0xfd, 0x9e, 0x2d, 0x27, 0x24, 0x1a, 0xae, 0x29,
	0x85, 0x3d, 0xd0, 0xbe, 0xc1, 0x1b, 0xe4, 0x3b, 0xb3, 0x54, 0xe9, 0x14, 0xb7, 0x6b, 0xcb, 0x6c,
	0x6f, 0xa5, 0x56, 0x17, 0x1c, 0x51, 0x94, 0x38, 0x62, 0x84, 0xf1, 0x5d, 0x02, 0xc7, 0x95, 0xe6,
	0x70, 0x3a, 0x1a, 0xf9, 0x01, 0x82, 0xdd, 0x7f, 0x41, 0x60, 0xcf, 0xfb, 0x12, 0x00, 0x4c, 0x9d,
	0x1b, 0xbc, 0x71, 0x67, 0x4b, 0xfe, 0xc8, 0x6d, 0xab, 0x9f, 0x67, 0xda, 0xff, 0xc2, 0xd5, 0x3b,
	0xde, 0x12, 0x57, 0xd1, 0xc1, 0xb4, 0xac, 0xc0, 0x37, 0x35, 0x2b, 0xfc, 0xa1, 0x8d, 0x3c, 0xd3,
	0xd4, 0x1a, 0x11, 0xf9, 0xba, 0x95, 0x72, 0xa6, 0xb8, 0x8f, 0xe2, 0x2c, 0x35, 0xc3, 0x73, 0x97,
	0x0d, 0x67, 0x22, 0xc6, 0x0f, 0x09, 0x9c, 0xde, 0x35, 0x3c, 0x0a, 0x93, 0x38, 0x85, 0x23, 0x70,
	0x54, 0x7d, 0x0c, 0xa7, 0x0a, 0xf2, 0xad, 0x71, 0xf5, 0x20, 0xd7, 0x22, 0x7c, 0x58, 0xf1, 0xc6,
	0x45, 0x96, 0x5b, 0xde, 0x1a, 0x15, 0x02, 0x3c, 0xcd, 0xbd, 0x3c, 0xd3, 0x4e, 0x2b, 0x81, 0xe9,
	0xa8, 0xc6, 0x3b, 0xf0, 0xd6, 0x68, 0xec, 0xc3, 0x27, 0xa0, 0x89, 0xfc, 0x00, 0xb1, 0xf3, 0x1d,
	0x5e, 0xf6, 0xaa, 0x04, 0xdd, 0xb5, 0x69, 0x33, 0x98, 0xf5, 0xfc, 0xe7, 0x56, 0x95, 0x7e, 0x6d,
	0x55, 0xe9, 0xf7, 0x56, 0x95, 0xbe, 0xfd, 0x51, 0xf7, 0x40, 0x0f, 0x93, 0x01, 0x4d, 0x5c, 0x6f,
	0x11, 0x93, 0x0d, 0xff, 0x9e, 0x42, 0xe3, 0x93, 0xf8, 0xda, 0xb3, 0x16, 0xab, 0x3f, 0xfb, 0x1b,
	0x00, 0x00, 0xff, 0xff, 0x85, 0xed, 0xc2, 0xb9, 0x0b, 0x04, 0x00, 0x00,
}

func (m *ImageComponent) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ImageComponent) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ImageComponent) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.FixedBy) > 0 {
		i -= len(m.FixedBy)
		copy(dAtA[i:], m.FixedBy)
		i = encodeVarintImageComponent(dAtA, i, uint64(len(m.FixedBy)))
		i--
		dAtA[i] = 0x4a
	}
	if m.SetTopCvss != nil {
		{
			size := m.SetTopCvss.Size()
			i -= size
			if _, err := m.SetTopCvss.MarshalTo(dAtA[i:]); err != nil {
				return 0, err
			}
		}
	}
	if m.RiskScore != 0 {
		i -= 4
		encoding_binary.LittleEndian.PutUint32(dAtA[i:], uint32(math.Float32bits(float32(m.RiskScore))))
		i--
		dAtA[i] = 0x3d
	}
	if m.Source != 0 {
		i = encodeVarintImageComponent(dAtA, i, uint64(m.Source))
		i--
		dAtA[i] = 0x30
	}
	if m.Priority != 0 {
		i = encodeVarintImageComponent(dAtA, i, uint64(m.Priority))
		i--
		dAtA[i] = 0x28
	}
	if m.License != nil {
		{
			size, err := m.License.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintImageComponent(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x22
	}
	if len(m.Version) > 0 {
		i -= len(m.Version)
		copy(dAtA[i:], m.Version)
		i = encodeVarintImageComponent(dAtA, i, uint64(len(m.Version)))
		i--
		dAtA[i] = 0x1a
	}
	if len(m.Name) > 0 {
		i -= len(m.Name)
		copy(dAtA[i:], m.Name)
		i = encodeVarintImageComponent(dAtA, i, uint64(len(m.Name)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.Id) > 0 {
		i -= len(m.Id)
		copy(dAtA[i:], m.Id)
		i = encodeVarintImageComponent(dAtA, i, uint64(len(m.Id)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *ImageComponent_TopCvss) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ImageComponent_TopCvss) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	i -= 4
	encoding_binary.LittleEndian.PutUint32(dAtA[i:], uint32(math.Float32bits(float32(m.TopCvss))))
	i--
	dAtA[i] = 0x45
	return len(dAtA) - i, nil
}
func (m *ComponentCVEEdge) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ComponentCVEEdge) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ComponentCVEEdge) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.HasFixedBy != nil {
		{
			size := m.HasFixedBy.Size()
			i -= size
			if _, err := m.HasFixedBy.MarshalTo(dAtA[i:]); err != nil {
				return 0, err
			}
		}
	}
	if m.IsFixable {
		i--
		if m.IsFixable {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x10
	}
	if len(m.Id) > 0 {
		i -= len(m.Id)
		copy(dAtA[i:], m.Id)
		i = encodeVarintImageComponent(dAtA, i, uint64(len(m.Id)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *ComponentCVEEdge_FixedBy) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ComponentCVEEdge_FixedBy) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	i -= len(m.FixedBy)
	copy(dAtA[i:], m.FixedBy)
	i = encodeVarintImageComponent(dAtA, i, uint64(len(m.FixedBy)))
	i--
	dAtA[i] = 0x1a
	return len(dAtA) - i, nil
}
func (m *ComponentCVEEdgeEntry) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ComponentCVEEdgeEntry) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ComponentCVEEdgeEntry) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.Edge != nil {
		{
			size, err := m.Edge.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintImageComponent(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x1a
	}
	if len(m.CveId) > 0 {
		i -= len(m.CveId)
		copy(dAtA[i:], m.CveId)
		i = encodeVarintImageComponent(dAtA, i, uint64(len(m.CveId)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.ComponentId) > 0 {
		i -= len(m.ComponentId)
		copy(dAtA[i:], m.ComponentId)
		i = encodeVarintImageComponent(dAtA, i, uint64(len(m.ComponentId)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintImageComponent(dAtA []byte, offset int, v uint64) int {
	offset -= sovImageComponent(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *ImageComponent) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Id)
	if l > 0 {
		n += 1 + l + sovImageComponent(uint64(l))
	}
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovImageComponent(uint64(l))
	}
	l = len(m.Version)
	if l > 0 {
		n += 1 + l + sovImageComponent(uint64(l))
	}
	if m.License != nil {
		l = m.License.Size()
		n += 1 + l + sovImageComponent(uint64(l))
	}
	if m.Priority != 0 {
		n += 1 + sovImageComponent(uint64(m.Priority))
	}
	if m.Source != 0 {
		n += 1 + sovImageComponent(uint64(m.Source))
	}
	if m.RiskScore != 0 {
		n += 5
	}
	if m.SetTopCvss != nil {
		n += m.SetTopCvss.Size()
	}
	l = len(m.FixedBy)
	if l > 0 {
		n += 1 + l + sovImageComponent(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *ImageComponent_TopCvss) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	n += 5
	return n
}
func (m *ComponentCVEEdge) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Id)
	if l > 0 {
		n += 1 + l + sovImageComponent(uint64(l))
	}
	if m.IsFixable {
		n += 2
	}
	if m.HasFixedBy != nil {
		n += m.HasFixedBy.Size()
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *ComponentCVEEdge_FixedBy) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.FixedBy)
	n += 1 + l + sovImageComponent(uint64(l))
	return n
}
func (m *ComponentCVEEdgeEntry) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.ComponentId)
	if l > 0 {
		n += 1 + l + sovImageComponent(uint64(l))
	}
	l = len(m.CveId)
	if l > 0 {
		n += 1 + l + sovImageComponent(uint64(l))
	}
	if m.Edge != nil {
		l = m.Edge.Size()
		n += 1 + l + sovImageComponent(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovImageComponent(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozImageComponent(x uint64) (n int) {
	return sovImageComponent(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *ImageComponent) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowImageComponent
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ImageComponent: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ImageComponent: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Id", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowImageComponent
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthImageComponent
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthImageComponent
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Id = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowImageComponent
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthImageComponent
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthImageComponent
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Version", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowImageComponent
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthImageComponent
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthImageComponent
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Version = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field License", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowImageComponent
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthImageComponent
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthImageComponent
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.License == nil {
				m.License = &License{}
			}
			if err := m.License.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 5:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Priority", wireType)
			}
			m.Priority = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowImageComponent
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Priority |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 6:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Source", wireType)
			}
			m.Source = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowImageComponent
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Source |= SourceType(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 7:
			if wireType != 5 {
				return fmt.Errorf("proto: wrong wireType = %d for field RiskScore", wireType)
			}
			var v uint32
			if (iNdEx + 4) > l {
				return io.ErrUnexpectedEOF
			}
			v = uint32(encoding_binary.LittleEndian.Uint32(dAtA[iNdEx:]))
			iNdEx += 4
			m.RiskScore = float32(math.Float32frombits(v))
		case 8:
			if wireType != 5 {
				return fmt.Errorf("proto: wrong wireType = %d for field TopCvss", wireType)
			}
			var v uint32
			if (iNdEx + 4) > l {
				return io.ErrUnexpectedEOF
			}
			v = uint32(encoding_binary.LittleEndian.Uint32(dAtA[iNdEx:]))
			iNdEx += 4
			m.SetTopCvss = &ImageComponent_TopCvss{float32(math.Float32frombits(v))}
		case 9:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field FixedBy", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowImageComponent
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthImageComponent
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthImageComponent
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.FixedBy = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipImageComponent(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthImageComponent
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ComponentCVEEdge) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowImageComponent
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ComponentCVEEdge: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ComponentCVEEdge: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Id", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowImageComponent
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthImageComponent
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthImageComponent
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Id = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field IsFixable", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowImageComponent
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.IsFixable = bool(v != 0)
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field FixedBy", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowImageComponent
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthImageComponent
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthImageComponent
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.HasFixedBy = &ComponentCVEEdge_FixedBy{string(dAtA[iNdEx:postIndex])}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipImageComponent(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthImageComponent
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ComponentCVEEdgeEntry) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowImageComponent
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ComponentCVEEdgeEntry: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ComponentCVEEdgeEntry: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ComponentId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowImageComponent
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthImageComponent
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthImageComponent
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ComponentId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field CveId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowImageComponent
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthImageComponent
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthImageComponent
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.CveId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Edge", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowImageComponent
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthImageComponent
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthImageComponent
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Edge == nil {
				m.Edge = &ComponentCVEEdge{}
			}
			if err := m.Edge.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipImageComponent(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthImageComponent
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipImageComponent(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowImageComponent
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowImageComponent
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowImageComponent
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthImageComponent
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupImageComponent
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthImageComponent
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthImageComponent        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowImageComponent          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupImageComponent = fmt.Errorf("proto: unexpected end of group")
)

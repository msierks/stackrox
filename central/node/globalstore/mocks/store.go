// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/stackrox/rox/central/node/globalstore (interfaces: GlobalStore)

// Package mocks is a generated GoMock package.
package mocks

import (
	gomock "github.com/golang/mock/gomock"
	store "github.com/stackrox/rox/central/node/store"
	v1 "github.com/stackrox/rox/generated/api/v1"
	search "github.com/stackrox/rox/pkg/search"
	reflect "reflect"
)

// MockGlobalStore is a mock of GlobalStore interface
type MockGlobalStore struct {
	ctrl     *gomock.Controller
	recorder *MockGlobalStoreMockRecorder
}

// MockGlobalStoreMockRecorder is the mock recorder for MockGlobalStore
type MockGlobalStoreMockRecorder struct {
	mock *MockGlobalStore
}

// NewMockGlobalStore creates a new mock instance
func NewMockGlobalStore(ctrl *gomock.Controller) *MockGlobalStore {
	mock := &MockGlobalStore{ctrl: ctrl}
	mock.recorder = &MockGlobalStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockGlobalStore) EXPECT() *MockGlobalStoreMockRecorder {
	return m.recorder
}

// CountAllNodes mocks base method
func (m *MockGlobalStore) CountAllNodes() (int, error) {
	ret := m.ctrl.Call(m, "CountAllNodes")
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CountAllNodes indicates an expected call of CountAllNodes
func (mr *MockGlobalStoreMockRecorder) CountAllNodes() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CountAllNodes", reflect.TypeOf((*MockGlobalStore)(nil).CountAllNodes))
}

// GetAllClusterNodeStores mocks base method
func (m *MockGlobalStore) GetAllClusterNodeStores() (map[string]store.Store, error) {
	ret := m.ctrl.Call(m, "GetAllClusterNodeStores")
	ret0, _ := ret[0].(map[string]store.Store)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAllClusterNodeStores indicates an expected call of GetAllClusterNodeStores
func (mr *MockGlobalStoreMockRecorder) GetAllClusterNodeStores() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAllClusterNodeStores", reflect.TypeOf((*MockGlobalStore)(nil).GetAllClusterNodeStores))
}

// GetClusterNodeStore mocks base method
func (m *MockGlobalStore) GetClusterNodeStore(arg0 string) (store.Store, error) {
	ret := m.ctrl.Call(m, "GetClusterNodeStore", arg0)
	ret0, _ := ret[0].(store.Store)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetClusterNodeStore indicates an expected call of GetClusterNodeStore
func (mr *MockGlobalStoreMockRecorder) GetClusterNodeStore(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetClusterNodeStore", reflect.TypeOf((*MockGlobalStore)(nil).GetClusterNodeStore), arg0)
}

// RemoveClusterNodeStores mocks base method
func (m *MockGlobalStore) RemoveClusterNodeStores(arg0 ...string) error {
	varargs := []interface{}{}
	for _, a := range arg0 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "RemoveClusterNodeStores", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// RemoveClusterNodeStores indicates an expected call of RemoveClusterNodeStores
func (mr *MockGlobalStoreMockRecorder) RemoveClusterNodeStores(arg0 ...interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveClusterNodeStores", reflect.TypeOf((*MockGlobalStore)(nil).RemoveClusterNodeStores), arg0...)
}

// Search mocks base method
func (m *MockGlobalStore) Search(arg0 *v1.Query) ([]search.Result, error) {
	ret := m.ctrl.Call(m, "Search", arg0)
	ret0, _ := ret[0].([]search.Result)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Search indicates an expected call of Search
func (mr *MockGlobalStoreMockRecorder) Search(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Search", reflect.TypeOf((*MockGlobalStore)(nil).Search), arg0)
}

// SearchResults mocks base method
func (m *MockGlobalStore) SearchResults(arg0 *v1.Query) ([]*v1.SearchResult, error) {
	ret := m.ctrl.Call(m, "SearchResults", arg0)
	ret0, _ := ret[0].([]*v1.SearchResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SearchResults indicates an expected call of SearchResults
func (mr *MockGlobalStoreMockRecorder) SearchResults(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SearchResults", reflect.TypeOf((*MockGlobalStore)(nil).SearchResults), arg0)
}

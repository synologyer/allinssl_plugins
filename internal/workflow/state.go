package workflow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// stateFileName 是模块数据目录下记录各节点上次部署情况的文件。
const stateFileName = "deployed.json"

// deployRecord 记录一个节点上次成功部署的证书和目标。
type deployRecord struct {
	CertHash   string `json:"cert_hash"`   // 证书内容的 SHA-256
	TargetHash string `json:"target_hash"` // 设备地址、证书描述、是否设为默认的摘要
	Time       string `json:"time"`
}

// stateStore 把各节点上次成功部署的记录保存在模块数据目录下，
// 用来实现与内置部署节点相同的「与上次部署的证书相同且上次部署成功时跳过」。
type stateStore struct {
	mu   sync.Mutex
	path string // 为空时不保存，每次都视为没有记录
}

var store = &stateStore{}

// SetDataDir 设置保存部署记录的目录，由程序入口传入宿主提供的模块数据目录。
func SetDataDir(dir string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if dir == "" {
		store.path = ""
		return
	}
	store.path = filepath.Join(dir, stateFileName)
}

func (s *stateStore) load() map[string]deployRecord {
	records := map[string]deployRecord{}
	if s.path == "" {
		return records
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return records
	}
	if err := json.Unmarshal(data, &records); err != nil {
		log.Printf("部署记录文件 %s 无法解析，按没有记录处理: %v", s.path, err)
		return map[string]deployRecord{}
	}
	return records
}

// matches 判断节点上次成功部署的是否就是这张证书、这个目标。
func (s *stateStore) matches(nodeID, certHash, targetHash string) bool {
	if nodeID == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.load()[nodeID]
	return ok && record.CertHash == certHash && record.TargetHash == targetHash
}

// save 记录节点的一次成功部署。
func (s *stateStore) save(nodeID, certHash, targetHash string) {
	if nodeID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" {
		return
	}
	records := s.load()
	records[nodeID] = deployRecord{CertHash: certHash, TargetHash: targetHash, Time: time.Now().Format(time.DateTime)}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		log.Printf("保存部署记录失败: %v", err)
		return
	}
	// 先写临时文件再改名，避免中途退出留下损坏的文件
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("保存部署记录失败: %v", err)
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		log.Printf("保存部署记录失败: %v", err)
	}
}

// forget 删除节点的部署记录，部署失败后调用，保证下次不会被跳过。
func (s *stateStore) forget(nodeID string) {
	if nodeID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" {
		return
	}
	records := s.load()
	if _, ok := records[nodeID]; !ok {
		return
	}
	delete(records, nodeID)
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err == nil {
		_ = os.Rename(tmp, s.path)
	}
}

func hashStrings(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		hash.Write([]byte(value))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

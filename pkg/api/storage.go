package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Storage 存储接口定义
type Storage interface {
	SaveScan(scan *ScanResponse) error
	GetScan(id string) (*ScanResponse, error)
	GetAllScans() ([]*ScanResponse, error)
	UpdateScan(scan *ScanResponse) error
	DeleteScan(id string) error
	Cleanup(maxAge time.Duration) (int, error)
}

// FileStorage 基于文件的存储实现
type FileStorage struct {
	baseDir string
	mutex   sync.RWMutex
	cache   map[string]*ScanResponse // 内存缓存
}

// NewFileStorage 创建文件存储
func NewFileStorage(baseDir string) (*FileStorage, error) {
	// 确保目录存在
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("创建存储目录失败: %v", err)
	}

	// 初始化缓存
	storage := &FileStorage{
		baseDir: baseDir,
		cache:   make(map[string]*ScanResponse),
	}

	// 加载现有数据到缓存
	if err := storage.loadCache(); err != nil {
		return nil, fmt.Errorf("加载缓存失败: %v", err)
	}

	return storage, nil
}

// loadCache 从文件系统加载数据到缓存
func (s *FileStorage) loadCache() error {
	files, err := os.ReadDir(s.baseDir)
	if err != nil {
		return err
	}

	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		id := filepath.Base(file.Name())
		id = id[:len(id)-5] // 移除 .json 后缀

		scan, err := s.loadScanFromFile(id)
		if err != nil {
			continue // 跳过错误文件
		}

		s.cache[id] = scan
	}

	return nil
}

// getScanFilePath 获取扫描结果文件路径
func (s *FileStorage) getScanFilePath(id string) string {
	return filepath.Join(s.baseDir, id+".json")
}

// loadScanFromFile 从文件加载扫描结果
func (s *FileStorage) loadScanFromFile(id string) (*ScanResponse, error) {
	filePath := s.getScanFilePath(id)

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var scan ScanResponse
	if err := json.Unmarshal(data, &scan); err != nil {
		return nil, err
	}

	return &scan, nil
}

// SaveScan 保存扫描结果
func (s *FileStorage) SaveScan(scan *ScanResponse) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 更新缓存
	s.cache[scan.ID] = scan

	// 序列化到JSON
	data, err := json.MarshalIndent(scan, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化数据失败: %v", err)
	}

	// 写入文件
	filePath := s.getScanFilePath(scan.ID)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("写入文件失败: %v", err)
	}

	return nil
}

// GetScan 获取扫描结果
func (s *FileStorage) GetScan(id string) (*ScanResponse, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// 先从缓存获取
	if scan, exists := s.cache[id]; exists {
		return scan, nil
	}

	// 缓存未命中，从文件加载
	scan, err := s.loadScanFromFile(id)
	if err != nil {
		return nil, fmt.Errorf("加载扫描结果失败: %v", err)
	}

	// 更新缓存
	s.cache[id] = scan
	return scan, nil
}

// GetAllScans 获取所有扫描结果
func (s *FileStorage) GetAllScans() ([]*ScanResponse, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	results := make([]*ScanResponse, 0, len(s.cache))
	for _, scan := range s.cache {
		results = append(results, scan)
	}

	return results, nil
}

// UpdateScan 更新扫描结果
func (s *FileStorage) UpdateScan(scan *ScanResponse) error {
	return s.SaveScan(scan) // 直接使用SaveScan实现
}

// DeleteScan 删除扫描结果
func (s *FileStorage) DeleteScan(id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 从缓存中删除
	delete(s.cache, id)

	// 删除文件
	filePath := s.getScanFilePath(id)
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除文件失败: %v", err)
	}

	return nil
}

// Cleanup 清理旧的扫描结果
func (s *FileStorage) Cleanup(maxAge time.Duration) (int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	cutoff := time.Now().Add(-maxAge)
	count := 0

	for id, scan := range s.cache {
		if scan.CreatedAt.Before(cutoff) {
			// 从缓存删除
			delete(s.cache, id)

			// 删除文件
			filePath := s.getScanFilePath(id)
			if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
				return count, fmt.Errorf("清理时删除文件失败: %v", err)
			}

			count++
		}
	}

	return count, nil
}

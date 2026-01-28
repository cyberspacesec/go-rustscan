package rustscan

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
)

// ParseNmapXML 解析nmap的XML输出文件并返回结构化数据
func ParseNmapXML(xmlFilePath string) (*NmapRun, error) {
	// 读取XML文件
	xmlData, err := os.ReadFile(xmlFilePath)
	if err != nil {
		return nil, fmt.Errorf("读取XML文件失败: %v", err)
	}

	// 解析XML数据
	var nmapRun NmapRun
	if err := xml.Unmarshal(xmlData, &nmapRun); err != nil {
		return nil, fmt.Errorf("解析XML数据失败: %v", err)
	}

	return &nmapRun, nil
}

// ConvertXMLToJSON 将XML文件转换为JSON文件
func ConvertXMLToJSON(xmlFilePath, jsonFilePath string) error {
	// 解析XML
	result, err := ParseNmapXML(xmlFilePath)
	if err != nil {
		return err
	}

	// 转换为JSON
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("转换为JSON失败: %v", err)
	}

	// 写入JSON文件
	if err := os.WriteFile(jsonFilePath, jsonData, 0644); err != nil {
		return fmt.Errorf("写入JSON文件失败: %v", err)
	}

	return nil
}

package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// NmapRun 表示nmap扫描结果的根元素
type NmapRun struct {
	XMLName        xml.Name  `xml:"nmaprun" json:"-"`
	Scanner        string    `xml:"scanner,attr" json:"scanner"`
	Args           string    `xml:"args,attr" json:"args"`
	Start          string    `xml:"start,attr" json:"start"`
	Startstr       string    `xml:"startstr,attr" json:"startstr"`
	Version        string    `xml:"version,attr" json:"version"`
	XmlOutputVersion string   `xml:"xmloutputversion,attr" json:"xml_output_version"`
	ScanInfo       ScanInfo  `xml:"scaninfo" json:"scan_info"`
	Verbose        Verbose   `xml:"verbose" json:"verbose"`
	Debugging      Debugging `xml:"debugging" json:"debugging"`
	TaskBegin      TaskBegin `xml:"taskbegin" json:"task_begin"`
	TaskEnd        TaskEnd   `xml:"taskend" json:"task_end"`
	Hosts          []Host    `xml:"host" json:"hosts"`
	RunStats       RunStats  `xml:"runstats" json:"run_stats"`
}

// ScanInfo 表示扫描信息
type ScanInfo struct {
	Type        string `xml:"type,attr" json:"type"`
	Protocol    string `xml:"protocol,attr" json:"protocol"`
	Numservices string `xml:"numservices,attr" json:"num_services"`
	Services    string `xml:"services,attr" json:"services"`
}

// Verbose 表示详细程度
type Verbose struct {
	Level string `xml:"level,attr" json:"level"`
}

// Debugging 表示调试信息
type Debugging struct {
	Level string `xml:"level,attr" json:"level"`
}

// TaskBegin 表示任务开始
type TaskBegin struct {
	Task string `xml:"task,attr" json:"task"`
	Time string `xml:"time,attr" json:"time"`
}

// TaskEnd 表示任务结束
type TaskEnd struct {
	Task      string `xml:"task,attr" json:"task"`
	Time      string `xml:"time,attr" json:"time"`
	ExtraInfo string `xml:"extrainfo,attr" json:"extra_info"`
}

// Host 表示主机信息
type Host struct {
	Status  Status  `xml:"status" json:"status"`
	Address Address `xml:"address" json:"address"`
	Ports   Ports   `xml:"ports,omitempty" json:"ports,omitempty"`
}

// Status 表示主机状态
type Status struct {
	State     string `xml:"state,attr" json:"state"`
	Reason    string `xml:"reason,attr" json:"reason"`
	ReasonTTL string `xml:"reason_ttl,attr" json:"reason_ttl"`
}

// Address 表示地址信息
type Address struct {
	Addr     string `xml:"addr,attr" json:"addr"`
	AddrType string `xml:"addrtype,attr" json:"addr_type"`
}

// Ports 表示端口信息集合
type Ports struct {
	Ports []Port `xml:"port" json:"ports"`
}

// Port 表示单个端口信息
type Port struct {
	Protocol string  `xml:"protocol,attr" json:"protocol"`
	PortID   string  `xml:"portid,attr" json:"port_id"`
	State    State   `xml:"state" json:"state"`
	Service  Service `xml:"service" json:"service"`
}

// State 表示端口状态
type State struct {
	State     string `xml:"state,attr" json:"state"`
	Reason    string `xml:"reason,attr" json:"reason"`
	ReasonTTL string `xml:"reason_ttl,attr" json:"reason_ttl"`
}

// Service 表示服务信息
type Service struct {
	Name   string `xml:"name,attr" json:"name"`
	Method string `xml:"method,attr" json:"method"`
	Conf   string `xml:"conf,attr" json:"conf"`
}

// RunStats 表示运行统计信息
type RunStats struct {
	Finished Finished `xml:"finished" json:"finished"`
	Hosts    Hosts    `xml:"hosts" json:"hosts"`
}

// Finished 表示扫描完成信息
type Finished struct {
	Time     string `xml:"time,attr" json:"time"`
	Timestr  string `xml:"timestr,attr" json:"timestr"`
	Summary  string `xml:"summary,attr" json:"summary"`
	Elapsed  string `xml:"elapsed,attr" json:"elapsed"`
	Exit     string `xml:"exit,attr" json:"exit"`
}

// Hosts 表示主机统计信息
type Hosts struct {
	Up    string `xml:"up,attr" json:"up"`
	Down  string `xml:"down,attr" json:"down"`
	Total string `xml:"total,attr" json:"total"`
}

// ConvertXMLToJSON 将XML文件转换为JSON文件
func ConvertXMLToJSON(xmlFilePath, jsonFilePath string) error {
	// 读取XML文件
	xmlData, err := ioutil.ReadFile(xmlFilePath)
	if err != nil {
		return fmt.Errorf("读取XML文件失败: %v", err)
	}

	// 解析XML数据
	var nmapRun NmapRun
	if err := xml.Unmarshal(xmlData, &nmapRun); err != nil {
		return fmt.Errorf("解析XML数据失败: %v", err)
	}

	// 转换为JSON
	jsonData, err := json.MarshalIndent(nmapRun, "", "  ")
	if err != nil {
		return fmt.Errorf("转换为JSON失败: %v", err)
	}

	// 写入JSON文件
	if err := ioutil.WriteFile(jsonFilePath, jsonData, 0644); err != nil {
		return fmt.Errorf("写入JSON文件失败: %v", err)
	}

	return nil
}

// ConvertXMLToJSONFile 是一个独立的函数，用于将XML文件转换为JSON文件
func ConvertXMLToJSONFile() {
	currentDir := "/Users/cc11001100/github/cyberspacesec/go-rustscan/"
	xmlFilePath := filepath.Join(currentDir, "result.xml")
	jsonFilePath := filepath.Join(currentDir, "result.json")

	// 检查XML文件是否存在
	if _, err := os.Stat(xmlFilePath); os.IsNotExist(err) {
		fmt.Printf("XML文件不存在: %s\n", xmlFilePath)
		os.Exit(1)
	}

	// 转换XML到JSON
	fmt.Println("开始转换XML到JSON...")
	if err := ConvertXMLToJSON(xmlFilePath, jsonFilePath); err != nil {
		fmt.Printf("转换失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("转换成功！JSON结果已保存到: %s\n", jsonFilePath)
}
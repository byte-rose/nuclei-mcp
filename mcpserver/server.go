ypackage mcpserver

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

type Server struct {
	info         Implementation
	capabilities ServerCapabilities
	tools        []Tool
	resources    []Resource
	templates    []ResourceTemplate
	mu           sync.RWMutex
	writer       io.Writer
	initialized  bool
}

func NewServer(writer io.Writer) *Server {
	return &Server{
		info: Implementation{
			Name:    "go-mcp-server",
			Version: "0.1.0",
		},
		capabilities: ServerCapabilities{
			Tools: &struct {
				ListChanged bool "json:\"listChanged,omitempty\""
			}{
				ListChanged: true,
			},
			Resources: &struct {
				Subscribe   bool "json:\"subscribe,omitempty\""
				ListChanged bool "json:\"listChanged,omitempty\""
			}{
				Subscribe:   true,
				ListChanged: true,
			},
		},
		writer: writer,
	}
}

func (s *Server) handleRequest(req *JSONRPCRequest) error {
	var response JSONRPCResponse
	response.JSONRPC = JsonRpcVersion
	response.ID = req.ID

	switch req.Method {
	case "initialize":
		var initReq InitializeRequest
		if err := json.Unmarshal(toJSON(req.Params), &initReq); err != nil {
			return s.sendError(req.ID, InvalidParams, "Invalid initialization parameters")
		}
		result := InitializeResult{
			ProtocolVersion: LatestProtocolVersion,
			Capabilities:    s.capabilities,
			ServerInfo:      s.info,
			Instructions:    "MCP server implemented in Go",
		}
		response.Result = result
		s.initialized = true

	case "tools/list":
		if !s.initialized {
			return s.sendError(req.ID, InvalidRequest, "Server not initialized")
		}
		s.mu.RLock()
		response.Result = map[string]interface{}{
			"tools": s.tools,
		}
		s.mu.RUnlock()

	case "tools/call":
		if !s.initialized {
			return s.sendError(req.ID, InvalidRequest, "Server not initialized")
		}
		var callReq CallToolRequest
		if err := json.Unmarshal(toJSON(req.Params), &callReq); err != nil {
			return s.sendError(req.ID, InvalidParams, "Invalid tool call parameters")
		}

		result, err := s.handleToolCall(&callReq)
		if err != nil {
			return s.sendError(req.ID, InternalError, err.Error())
		}
		response.Result = result

	case "resources/list":
		if !s.initialized {
			return s.sendError(req.ID, InvalidRequest, "Server not initialized")
		}
		s.mu.RLock()
		response.Result = map[string]interface{}{
			"resources": s.resources,
		}
		s.mu.RUnlock()

	case "resources/templates/list":
		if !s.initialized {
			return s.sendError(req.ID, InvalidRequest, "Server not initialized")
		}
		s.mu.RLock()
		response.Result = map[string]interface{}{
			"resourceTemplates": s.templates,
		}
		s.mu.RUnlock()

	case "ping":
		response.Result = struct{}{}

	default:
		return s.sendError(req.ID, MethodNotFound, fmt.Sprintf("Method not found: %s", req.Method))
	}

	return s.sendResponse(&response)
}

func (s *Server) handleToolCall(req *CallToolRequest) (*CallToolResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Find the requested tool
	var tool *Tool
	for _, t := range s.tools {
		if t.Name == req.Name {
			tool = &t
			break
		}
	}

	if tool == nil {
		return nil, fmt.Errorf("tool not found: %s", req.Name)
	}

	// This is where you would implement the actual tool functionality
	return &CallToolResult{
		Content: []Content{
			{
				Type: ContentTypeText,
				Text: fmt.Sprintf("Tool '%s' executed with arguments: %v", req.Name, req.Arguments),
			},
		},
		IsError: false,
	}, nil
}

func (s *Server) RegisterTool(tool Tool) {
	s.mu.Lock()
	s.tools = append(s.tools, tool)
	s.mu.Unlock()

	// Notify clients that the tool list has changed
	s.sendNotification("notifications/tools/list_changed", nil)
}

func (s *Server) RegisterResource(resource Resource) {
	s.mu.Lock()
	s.resources = append(s.resources, resource)
	s.mu.Unlock()

	// Notify clients that the resource list has changed
	s.sendNotification("notifications/resources/list_changed", nil)
}

func (s *Server) sendError(id RequestID, code int, message string) error {
	response := JSONRPCResponse{
		JSONRPC: JsonRpcVersion,
		ID:      id,
		Error: &struct {
			Code    int         "json:\"code\""
			Message string      "json:\"message\""
			Data    interface{} "json:\"data,omitempty\""
		}{
			Code:    code,
			Message: message,
		},
	}
	return s.sendResponse(&response)
}

func (s *Server) sendResponse(response *JSONRPCResponse) error {
	data, err := json.Marshal(response)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(s.writer, string(data))
	return err
}

func (s *Server) sendNotification(method string, params interface{}) error {
	notification := struct {
		JSONRPC string      `json:"jsonrpc"`
		Method  string      `json:"method"`
		Params  interface{} `json:"params,omitempty"`
	}{
		JSONRPC: JsonRpcVersion,
		Method:  method,
		Params:  params,
	}

	data, err := json.Marshal(notification)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(s.writer, string(data))
	return err
}

func (s *Server) Start() {
	decoder := json.NewDecoder(os.Stdin)
	for {
		var req JSONRPCRequest
		if err := decoder.Decode(&req); err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Error decoding request: %v", err)
			continue
		}

		if err := s.handleRequest(&req); err != nil {
			log.Printf("Error handling request: %v", err)
		}
	}
}

// Helper function to convert interface{} to JSON
func toJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

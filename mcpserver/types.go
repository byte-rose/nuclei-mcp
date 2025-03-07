package mcpserver

// Constants
const (
	LatestProtocolVersion = "DRAFT-2025-v1"
	JsonRpcVersion        = "2.0"

	// Standard JSON-RPC error codes
	ParseError     = -32700
	InvalidRequest = -32600
	MethodNotFound = -32601
	InvalidParams  = -32602
	InternalError  = -32603
)

// RequestID represents a uniquely identifying ID for a request in JSON-RPC
type RequestID interface{} // string or number

// ProgressToken represents a token used for progress notifications
type ProgressToken interface{} // string or number

// Cursor represents an opaque token used for pagination
type Cursor string

// Role represents the sender or recipient in conversations
type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// LoggingLevel represents severity levels for logging
type LoggingLevel string

const (
	LogDebug     LoggingLevel = "debug"
	LogInfo      LoggingLevel = "info"
	LogNotice    LoggingLevel = "notice"
	LogWarning   LoggingLevel = "warning"
	LogError     LoggingLevel = "error"
	LogCritical  LoggingLevel = "critical"
	LogAlert     LoggingLevel = "alert"
	LogEmergency LoggingLevel = "emergency"
)

// Base types
type Meta map[string]interface{}

type Implementation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Request/Response types
type Request struct {
	Method string `json:"method"`
	Params struct {
		Meta Meta `json:"_meta,omitempty"`
	} `json:"params,omitempty"`
}

type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      RequestID   `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      RequestID   `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *struct {
		Code    int         `json:"code"`
		Message string      `json:"message"`
		Data    interface{} `json:"data,omitempty"`
	} `json:"error,omitempty"`
}

// Initialize types
type ClientCapabilities struct {
	Experimental map[string]interface{} `json:"experimental,omitempty"`
	Roots        *struct {
		ListChanged bool `json:"listChanged,omitempty"`
	} `json:"roots,omitempty"`
	Sampling interface{} `json:"sampling,omitempty"`
}

type ServerCapabilities struct {
	Experimental map[string]interface{} `json:"experimental,omitempty"`
	Logging      interface{}            `json:"logging,omitempty"`
	Prompts      *struct {
		ListChanged bool `json:"listChanged,omitempty"`
	} `json:"prompts,omitempty"`
	Resources *struct {
		Subscribe   bool `json:"subscribe,omitempty"`
		ListChanged bool `json:"listChanged,omitempty"`
	} `json:"resources,omitempty"`
	Tools *struct {
		ListChanged bool `json:"listChanged,omitempty"`
	} `json:"tools,omitempty"`
}

type InitializeRequest struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ClientCapabilities `json:"capabilities"`
	ClientInfo      Implementation     `json:"clientInfo"`
}

type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      Implementation     `json:"serverInfo"`
	Instructions    string             `json:"instructions,omitempty"`
}

// Tool types
type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

type CallToolRequest struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

type CallToolResult struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

// Content types
type ContentType string

const (
	ContentTypeText  ContentType = "text"
	ContentTypeImage ContentType = "image"
	ContentTypeAudio ContentType = "audio"
)

type Content struct {
	Type        ContentType       `json:"type"`
	Text        string            `json:"text,omitempty"`
	Data        string            `json:"data,omitempty"`
	MimeType    string            `json:"mimeType,omitempty"`
	Resource    *ResourceContents `json:"resource,omitempty"`
	Annotations *Annotations      `json:"annotations,omitempty"`
}

type Annotations struct {
	Audience []Role  `json:"audience,omitempty"`
	Priority float64 `json:"priority,omitempty"`
}

// Resource types
type Resource struct {
	URI         string       `json:"uri"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	MimeType    string       `json:"mimeType,omitempty"`
	Annotations *Annotations `json:"annotations,omitempty"`
}

type ResourceTemplate struct {
	URITemplate string       `json:"uriTemplate"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	MimeType    string       `json:"mimeType,omitempty"`
	Annotations *Annotations `json:"annotations,omitempty"`
}

type ResourceContents struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"`
}

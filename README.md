# Nuclei MCP Integration

A Model Context Protocol (MCP) server implementation that integrates Nuclei, a fast and customizable vulnerability scanner, with the MCP ecosystem. This server provides a standardized interface for performing security scans and managing vulnerability assessments programmatically.

## 🚀 Features

- **Vulnerability Scanning**: Perform comprehensive security scans using Nuclei's powerful scanning engine
- **Template Management**: Add, list, and manage custom Nuclei templates
- **Result Caching**: Configurable caching system to optimize repeated scans
- **Concurrent Operations**: Thread-safe implementation for high-performance scanning
- **RESTful API**: Standardized interface for integration with other MCP-compliant tools
- **Detailed Reporting**: Structured vulnerability reports with severity levels and remediation guidance

## 🛠️ Tools & Endpoints

### Core Tools

- **nuclei_scan**: Perform a full Nuclei scan with advanced filtering options
- **basic_scan**: Quick scan with minimal configuration
- **vulnerability_resource**: Query and retrieve scan results
- **add_template**: Add custom Nuclei templates
- **list_templates**: View available templates
- **get_template**: Retrieve details of a specific template

## 🚀 Getting Started

### Prerequisites

- Go 1.16+
- Nuclei (will be automatically downloaded if not present)
- Node.js 14+ (for MCP Inspector)

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/your-org/nuclei-mcp.git
   cd nuclei-mcp
   ```

2. Install dependencies:

   ```bash
   go mod download
   ```

### Running the Server

Start the MCP server:

```bash
go run cmd/nuclei-mcp/main.go
```

### Using the MCP Inspector

For development and testing, use the MCP Inspector:

```bash
# Install the MCP Inspector globally
npm install -g @modelcontextprotocol/inspector

# Start the inspector with the Nuclei MCP server
npx @modelcontextprotocol/inspector go run cmd/nuclei-mcp/main.go
```

The inspector UI will be available at [http://localhost:5173](http://localhost:5173)

## ⚙️ Configuration

Configuration is managed through environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `CACHE_EXPIRY` | Duration for cache expiry | 1h |
| `LOG_LEVEL` | Logging level (debug, info, warn, error) | info |
| `LOG_PATH` | Path to log file | ./logs/nuclei-mcp.log |

## 📚 Documentation

- [MCP Protocol Documentation](https://modelcontextprotocol.io)
- [Nuclei Documentation](https://nuclei.projectdiscovery.io/)
- [API Reference](./docs/API.md)

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](./CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [MCP Go](https://github.com/mark3labs/mcp-go)

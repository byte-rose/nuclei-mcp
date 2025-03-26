# Nuclei MCP Server

This is a Mark3 Labs MCP server implementation for Nuclei, a fast and customizable vulnerability scanner.

## Features

- **Caching**: Scan results are cached with configurable expiry to improve performance
- **Thread-safe**: Supports concurrent scanning operations
- **Template filtering**: Allows filtering by severity, protocols, and template IDs
- **Basic & Advanced Scanning**: Provides both simple and advanced scanning options

## Usage

The server provides the following tools:

1. **nuclei_scan**: Perform a full Nuclei scan with template filtering
2. **basic_scan**: Perform a simple scan without template IDs
3. **vulnerability_resource**: Query scan results as resources
4. **advanced_scan**: Perform a comprehensive scan with extensive configuration options
5. **template_sources_scan**: Perform scans using custom template sources

## Running the Server

You can run the server directly using Go:

```bash
# From the nuclei directory
go run nuclei_mcp.go
```

## Using the MCP Inspector

The MCP Inspector is a powerful tool for debugging and testing your MCP server. To use it with the Nuclei MCP server:

```bash
# Install the MCP Inspector (if not already installed)
npm install -g @modelcontextprotocol/inspector

# Run the inspector with the Nuclei MCP server
npx @modelcontextprotocol/inspector go run ./nuclei_mcp.go
```

This will:
1. Start the MCP Inspector UI (available at http://localhost:5173)
2. Launch the Nuclei MCP server
3. Connect the inspector to the server

In the inspector UI, you can:
- View available tools and their schemas
- Execute tool calls and view results
- Inspect resources provided by the server
- Monitor server notifications

## Configuration

Configure the server via environment variables:

- `CACHE_EXPIRY`: Duration for cache expiry (default: 1h)
- `LOG_LEVEL`: Logging level (default: info)

## API

The server implements the standard MCP server interface. See the mpc package here:  [Mark3 Labs MCP documentation](https://github.com/mark3labs/mcp-go) for details.

"""Tests for CLI flags (transport, port, host)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from ghidra_mcp.__main__ import main


class TestCLITransportFlags:
    """Verify --transport, --port, --host are parsed and forwarded correctly."""

    @patch("ghidra_mcp.__main__.create_server")
    def test_default_transport_is_stdio(self, mock_create_server):
        mock_server = MagicMock()
        mock_create_server.return_value = mock_server
        with patch("sys.argv", ["ghidra-mcp"]):
            main()
        mock_server.run.assert_called_once_with(transport="stdio")

    @patch("ghidra_mcp.__main__.create_server")
    def test_transport_sse(self, mock_create_server):
        mock_server = MagicMock()
        mock_create_server.return_value = mock_server
        with patch("sys.argv", ["ghidra-mcp", "--transport", "sse"]):
            main()
        mock_server.run.assert_called_once_with(transport="sse")

    @patch("ghidra_mcp.__main__.create_server")
    def test_port_passed_to_create_server(self, mock_create_server):
        mock_server = MagicMock()
        mock_create_server.return_value = mock_server
        with patch("sys.argv", ["ghidra-mcp", "--port", "3000"]):
            main()
        mock_create_server.assert_called_once_with(
            project_dir="./ghidra-projects",
            project_name="mcp_project",
            mode="full",
            host="localhost",
            port=3000,
        )

    @patch("ghidra_mcp.__main__.create_server")
    def test_host_passed_to_create_server(self, mock_create_server):
        mock_server = MagicMock()
        mock_create_server.return_value = mock_server
        with patch("sys.argv", ["ghidra-mcp", "--host", "0.0.0.0"]):
            main()
        mock_create_server.assert_called_once_with(
            project_dir="./ghidra-projects",
            project_name="mcp_project",
            mode="full",
            host="0.0.0.0",
            port=8080,
        )

    @patch("ghidra_mcp.__main__.create_server")
    def test_default_port_is_8080(self, mock_create_server):
        mock_server = MagicMock()
        mock_create_server.return_value = mock_server
        with patch("sys.argv", ["ghidra-mcp"]):
            main()
        _, kwargs = mock_create_server.call_args
        assert kwargs["port"] == 8080

    @patch("ghidra_mcp.__main__.create_server")
    def test_default_host_is_localhost(self, mock_create_server):
        mock_server = MagicMock()
        mock_create_server.return_value = mock_server
        with patch("sys.argv", ["ghidra-mcp"]):
            main()
        _, kwargs = mock_create_server.call_args
        assert kwargs["host"] == "localhost"

    @patch("ghidra_mcp.__main__.create_server")
    def test_mode_code_still_works(self, mock_create_server):
        mock_server = MagicMock()
        mock_create_server.return_value = mock_server
        with patch("sys.argv", ["ghidra-mcp", "--mode", "code"]):
            main()
        mock_create_server.assert_called_once_with(
            project_dir="./ghidra-projects",
            project_name="mcp_project",
            mode="code",
            host="localhost",
            port=8080,
        )

# SPDX-License-Identifier: MIT
"""Tests for P2-1 RetrofitScanner and P2-3 Interceptor detection."""

from __future__ import annotations

from pathlib import Path

from engine.extraction.retrofit_scanner import (
    RetrofitScanner,
    _extract_static_headers,
    _scan_file,
    _scan_interceptor,
)
from engine.ir.models import Direction, TransportType

# ── helpers ────────────────────────────────────────────────────────────────────


def _java(tmp_path: Path, name: str, content: str) -> Path:
    """Write a .java file into tmp_path/sources/com/test/ and return apk_out_dir."""
    pkg = tmp_path / "sources" / "com" / "test"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / name).write_text(content)
    return tmp_path


# ── _extract_static_headers ───────────────────────────────────────────────────


def test_extract_static_headers_single() -> None:
    src = '@Headers({"Content-Type: application/json"})'
    headers = _extract_static_headers(src)
    assert headers["Content-Type"] == "application/json"


def test_extract_static_headers_multiple() -> None:
    src = '@Headers({"Content-Type: application/json", "Accept: application/json"})'
    headers = _extract_static_headers(src)
    assert headers["Content-Type"] == "application/json"
    assert headers["Accept"] == "application/json"


def test_extract_static_headers_empty_block() -> None:
    assert _extract_static_headers("no headers here") == {}


# ── _scan_file: verb + path ────────────────────────────────────────────────────


def test_scan_file_post_endpoint() -> None:
    src = """
    public interface DeviceApi {
        @POST("/api/v1/power")
        Call<PowerResponse> setPower(@Body PowerRequest body);
    }
    """
    eps = _scan_file(src, "DeviceApi")
    assert len(eps) == 1
    assert eps[0].http_verb == "POST"
    assert eps[0].path == "/api/v1/power"


def test_scan_file_get_endpoint() -> None:
    src = """
    @GET("/api/v1/status")
    Call<StatusResponse> getStatus();
    """
    eps = _scan_file(src, "DeviceApi")
    assert len(eps) == 1
    assert eps[0].http_verb == "GET"
    assert eps[0].path == "/api/v1/status"


def test_scan_file_multiple_verbs() -> None:
    src = """
    @GET("/api/v1/status")
    Call<StatusResponse> getStatus();

    @POST("/api/v1/power")
    Call<Void> setPower(@Body PowerRequest body);

    @DELETE("/api/v1/session")
    Call<Void> logout();
    """
    eps = _scan_file(src, "DeviceApi")
    verbs = {ep.http_verb for ep in eps}
    assert verbs == {"GET", "POST", "DELETE"}


def test_scan_file_case_insensitive_verb() -> None:
    src = '@get("/api/v1/ping")\nCall<Void> ping();'
    eps = _scan_file(src, "DeviceApi")
    assert eps[0].http_verb == "GET"


# ── _scan_file: body type ─────────────────────────────────────────────────────


def test_scan_file_body_type_extracted() -> None:
    src = """
    @POST("/api/v1/control")
    Call<ControlResponse> control(@Body ControlRequest body);
    """
    eps = _scan_file(src, "DeviceApi")
    assert eps[0].body_type == "ControlRequest"


def test_scan_file_no_body_when_absent() -> None:
    src = """
    @GET("/api/v1/status")
    Call<StatusResponse> getStatus();
    """
    eps = _scan_file(src, "DeviceApi")
    assert eps[0].body_type is None


# ── _scan_file: response type ─────────────────────────────────────────────────


def test_scan_file_response_type_extracted() -> None:
    src = """
    @GET("/api/v1/status")
    Call<DeviceStatus> getStatus();
    """
    eps = _scan_file(src, "DeviceApi")
    assert eps[0].response_type == "DeviceStatus"


def test_scan_file_observable_response_type() -> None:
    src = """
    @GET("/api/v1/stream")
    Observable<StreamEvent> stream();
    """
    eps = _scan_file(src, "DeviceApi")
    assert eps[0].response_type == "StreamEvent"


# ── _scan_file: header annotations ────────────────────────────────────────────


def test_scan_file_static_headers_extracted() -> None:
    src = """
    @Headers({"Content-Type: application/json", "Accept: application/json"})
    @POST("/api/v1/control")
    Call<Void> control(@Body ControlRequest body);
    """
    eps = _scan_file(src, "DeviceApi")
    assert eps[0].static_headers.get("Content-Type") == "application/json"


def test_scan_file_dynamic_header_param() -> None:
    src = """
    @GET("/api/v1/data")
    Call<Data> getData(@Header("X-API-Key") String apiKey);
    """
    eps = _scan_file(src, "DeviceApi")
    assert "X-API-Key" in eps[0].dynamic_headers


def test_scan_file_header_map_detected() -> None:
    src = """
    @POST("/api/v1/upload")
    Call<Void> upload(@HeaderMap Map<String, String> headers, @Body UploadRequest body);
    """
    eps = _scan_file(src, "DeviceApi")
    assert eps[0].has_header_map is True


def test_scan_file_no_header_map_when_absent() -> None:
    src = """
    @POST("/api/v1/simple")
    Call<Void> simple(@Body SimpleRequest body);
    """
    eps = _scan_file(src, "DeviceApi")
    assert eps[0].has_header_map is False


# ── _scan_file: interface name ─────────────────────────────────────────────────


def test_scan_file_interface_name_set() -> None:
    src = '@POST("/api/v1/power")\nCall<Void> power(@Body Req r);'
    eps = _scan_file(src, "MyApiService")
    assert eps[0].interface_name == "MyApiService"


# ── _scan_interceptor (P2-3) ───────────────────────────────────────────────────


def test_scan_interceptor_detects_implements() -> None:
    src = """
    public class AuthInterceptor implements Interceptor {
        @Override
        public Response intercept(Chain chain) throws IOException {
            Request req = chain.request().newBuilder()
                .addHeader("Authorization", "Bearer " + token)
                .addHeader("X-App-Version", "1.2.3")
                .build();
            return chain.proceed(req);
        }
    }
    """
    result = _scan_interceptor(src, "AuthInterceptor")
    assert result is not None
    assert result.class_name == "AuthInterceptor"
    assert "Authorization" in result.injected_headers
    assert "X-App-Version" in result.injected_headers


def test_scan_interceptor_returns_none_when_not_interceptor() -> None:
    src = """
    public class ApiService {
        void doSomething() { }
    }
    """
    assert _scan_interceptor(src, "ApiService") is None


def test_scan_interceptor_header_method_variant() -> None:
    src = """
    public class TokenInterceptor implements Interceptor {
        public Response intercept(Chain chain) {
            return chain.proceed(chain.request().newBuilder()
                .header("Authorization", "token " + apiToken)
                .build());
        }
    }
    """
    result = _scan_interceptor(src, "TokenInterceptor")
    assert result is not None
    assert "Authorization" in result.injected_headers


def test_scan_interceptor_no_headers_still_detected() -> None:
    src = """
    public class LoggingInterceptor implements Interceptor {
        public Response intercept(Chain chain) {
            return chain.proceed(chain.request());
        }
    }
    """
    result = _scan_interceptor(src, "LoggingInterceptor")
    assert result is not None
    assert result.injected_headers == []


# ── RetrofitScanner.scan() (filesystem integration) ───────────────────────────


def test_scanner_scan_finds_endpoints(tmp_path: Path) -> None:
    apk_dir = _java(
        tmp_path,
        "DeviceService.java",
        """
    public interface DeviceService {
        @GET("/api/v1/status")
        Call<StatusResp> getStatus();

        @POST("/api/v1/power")
        Call<Void> setPower(@Body PowerReq body);
    }
    """,
    )
    scanner = RetrofitScanner(apk_dir)
    endpoints, interceptors = scanner.scan("com.test")
    assert len(endpoints) == 2
    assert interceptors == []


def test_scanner_scan_finds_interceptor(tmp_path: Path) -> None:
    apk_dir = _java(
        tmp_path,
        "AuthInterceptor.java",
        """
    public class AuthInterceptor implements Interceptor {
        public Response intercept(Chain chain) {
            return chain.proceed(chain.request().newBuilder()
                .addHeader("X-Token", token).build());
        }
    }
    """,
    )
    scanner = RetrofitScanner(apk_dir)
    _endpoints, interceptors = scanner.scan("com.test")
    assert len(interceptors) == 1
    assert interceptors[0].class_name == "AuthInterceptor"


def test_scanner_to_ir_endpoints(tmp_path: Path) -> None:
    apk_dir = _java(
        tmp_path,
        "DeviceService.java",
        """
    public interface DeviceService {
        @POST("/api/v1/power")
        Call<PowerResponse> setPower(@Body PowerRequest body);
    }
    """,
    )
    scanner = RetrofitScanner(apk_dir)
    ret_eps, _ = scanner.scan("com.test")
    ir_eps = scanner.to_ir_endpoints(ret_eps)
    assert len(ir_eps) == 1
    ep = ir_eps[0]
    assert ep.transport == TransportType.HTTP_REST
    assert ep.direction == Direction.TO_DEVICE
    assert "POST" in ep.cmd
    assert "/api/v1/power" in ep.cmd


def test_scanner_to_ir_dynamic_header_becomes_field(tmp_path: Path) -> None:
    apk_dir = _java(
        tmp_path,
        "DeviceService.java",
        """
    public interface DeviceService {
        @GET("/api/v1/data")
        Call<DataResponse> getData(@Header("X-API-Key") String apiKey);
    }
    """,
    )
    scanner = RetrofitScanner(apk_dir)
    ret_eps, _ = scanner.scan("com.test")
    ir_eps = scanner.to_ir_endpoints(ret_eps)
    field_names = {f.serialized_name for f in ir_eps[0].request_fields}
    assert "X-API-Key" in field_names

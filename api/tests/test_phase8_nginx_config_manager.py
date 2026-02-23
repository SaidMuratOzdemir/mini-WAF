from types import SimpleNamespace

import pytest

from app.services.nginx_config_manager import NginxConfigManager


def _site(**overrides):
    base = {
        "id": 101,
        "host": "app.example.com",
        "upstream_url": "http://upstream.internal:8080",
        "is_active": True,
        "preserve_host_header": False,
        "enable_sni": True,
        "websocket_enabled": True,
        "sse_enabled": False,
        "body_inspection_profile": "default",
        "client_max_body_size_mb": None,
        "proxy_request_buffering": None,
        "proxy_read_timeout_sec": 60,
        "proxy_send_timeout_sec": 60,
        "proxy_connect_timeout_sec": 10,
        "proxy_redirect_mode": "default",
        "cookie_rewrite_enabled": False,
        "waf_decision_mode": "fail_close",
        "tls_enabled": False,
        "http_redirect_to_https": False,
        "upstream_tls_verify": True,
        "upstream_tls_server_name_override": None,
        "hsts_enabled": False,
        "xss_enabled": True,
        "sql_enabled": True,
        "vt_enabled": False,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.mark.parametrize(
    "profile,expected_size,forward_body,request_buffering",
    [
        ("strict", "client_max_body_size 1m;", "proxy_pass_request_body on;", "proxy_request_buffering on;"),
        ("default", "client_max_body_size 5m;", "proxy_pass_request_body on;", "proxy_request_buffering on;"),
        ("headers_only", "client_max_body_size 10m;", "proxy_pass_request_body off;", "proxy_request_buffering on;"),
        ("upload_friendly", "client_max_body_size 100m;", "proxy_pass_request_body off;", "proxy_request_buffering off;"),
    ],
)
def test_phase8_renders_body_profiles(profile, expected_size, forward_body, request_buffering, tmp_path):
    manager = NginxConfigManager(generated_config_dir=tmp_path)
    rendered = manager.render_site_config(_site(body_inspection_profile=profile))

    assert f"proxy_set_header X-WAF-Inspection-Profile {profile};" in rendered
    assert expected_size in rendered
    assert forward_body in rendered
    assert request_buffering in rendered


def test_phase8_renders_sse_and_timeout_tuning(tmp_path):
    manager = NginxConfigManager(generated_config_dir=tmp_path)
    rendered = manager.render_site_config(
        _site(
            sse_enabled=True,
            websocket_enabled=False,
            proxy_read_timeout_sec=120,
            proxy_send_timeout_sec=90,
            proxy_connect_timeout_sec=20,
        )
    )

    assert "proxy_read_timeout 120s;" in rendered
    assert "proxy_send_timeout 90s;" in rendered
    assert "proxy_connect_timeout 20s;" in rendered
    assert "proxy_buffering off;" in rendered
    assert "proxy_cache off;" in rendered
    assert "add_header X-Accel-Buffering no;" in rendered
    assert "proxy_set_header Upgrade $http_upgrade;" not in rendered


def test_phase8_renders_redirect_and_cookie_modes(tmp_path):
    manager = NginxConfigManager(generated_config_dir=tmp_path)
    rendered = manager.render_site_config(
        _site(
            proxy_redirect_mode="rewrite_to_public_host",
            cookie_rewrite_enabled=True,
        )
    )

    assert "proxy_redirect ~^https?://[^/]+(/.*)$ $scheme://$host$1;" in rendered
    assert "proxy_cookie_domain ~(?i)^(.+)$ $host;" in rendered
    assert "proxy_cookie_path / /;" in rendered


def test_phase8_renders_waf_decision_modes(tmp_path):
    manager = NginxConfigManager(generated_config_dir=tmp_path)
    fail_open_rendered = manager.render_site_config(_site(waf_decision_mode="fail_open"))
    fail_close_rendered = manager.render_site_config(_site(waf_decision_mode="fail_close"))

    assert "error_page 500 502 503 504 = @waf_allow;" in fail_open_rendered
    assert "error_page 500 502 503 504 = @waf_forbidden;" in fail_close_rendered
    assert "location @waf_allow {" in fail_open_rendered


def test_phase8_respects_explicit_overrides(tmp_path):
    manager = NginxConfigManager(generated_config_dir=tmp_path)
    rendered = manager.render_site_config(
        _site(
            body_inspection_profile="upload_friendly",
            client_max_body_size_mb=250,
            proxy_request_buffering=True,
        )
    )

    assert "client_max_body_size 250m;" in rendered
    assert "proxy_request_buffering on;" in rendered

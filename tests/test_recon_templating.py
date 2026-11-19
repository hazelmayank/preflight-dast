from preflight.recon.api_map import ApiMap, normalize_js_template, path_params, templatize
from preflight.recon.js_parser import add_js_to_map


def test_version_segments_are_not_ids():
    assert templatize("/api/v1/search") == "/api/v1/search"
    assert templatize("/api/v0/bookings/BK-1001") == "/api/v0/bookings/{booking_id}"


def test_ids_become_named_params():
    assert templatize("/api/v1/bookings/BK-3001/pay") == "/api/v1/bookings/{booking_id}/pay"
    assert templatize("/api/v1/admin/tenants/T2/users") == "/api/v1/admin/tenants/{tenant_id}/users"
    assert templatize("/api/v1/users/u3") == "/api/v1/users/{user_id}"
    assert templatize("/api/v1/invoices/INV-1002") == "/api/v1/invoices/{invoice_id}"
    assert templatize("/api/v1/search?city=Goa") == "/api/v1/search"
    assert path_params("/a/{booking_id}/b/{x_id}") == ["booking_id", "x_id"]


def test_js_template_literals():
    assert normalize_js_template("/api/v1/bookings/${id}/refunds") == "/api/v1/bookings/{booking_id}/refunds"
    assert normalize_js_template("/api/v1/search?city=${c}") == "/api/v1/search"


def test_js_parser_finds_calls_and_body_fields():
    js = (
        'const API = "/api/v1";\n'
        "const call = (m, p, b) => fetch(API + p, {method: m});\n"
        'export const a = (e, p) => call("POST", "/auth/login", {email, password});\n'
        'export const s = (c) => call("GET", `/search?city=${c}`);\n'
        'export const x = (id) => call("POST", `/bookings/${id}/pay`, {amount});\n'
    )
    amap = ApiMap()
    assert add_js_to_map(amap, js) == 3
    assert set(amap.get("POST", "/api/v1/auth/login").body_fields) == {"email", "password"}
    assert "city" in amap.get("GET", "/api/v1/search").query_params
    assert amap.get("POST", "/api/v1/bookings/{booking_id}/pay") is not None

#!/usr/bin/env python3
"""Read-only SonarQube Server configuration inventory for migration assessments."""

from __future__ import annotations

import json
import logging
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger("sonar_inventory")
PAGE_SIZE = 500


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized not in {"true", "false"}:
        raise ValueError(f"{name} debe ser true o false.")
    return normalized == "true"


@dataclass(frozen=True)
class Config:
    sonar_url: str
    sonar_token: str
    output_dir: Path
    verify_ssl: bool
    timeout: float
    log_level: str

    @classmethod
    def from_env(cls) -> Config:
        url = os.getenv("SONAR_URL", "").strip().rstrip("/")
        token = os.getenv("SONAR_TOKEN", "").strip()
        if not url:
            raise ValueError("Falta la variable requerida SONAR_URL.")
        if not token:
            raise ValueError("Falta la variable requerida SONAR_TOKEN.")
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("SONAR_URL debe ser una URL HTTP o HTTPS válida.")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError(
                "SONAR_URL no debe incluir credenciales, parámetros de consulta ni fragmentos."
            )
        try:
            timeout = float(os.getenv("REQUEST_TIMEOUT", "30"))
        except ValueError as exc:
            raise ValueError("REQUEST_TIMEOUT debe ser un número positivo.") from exc
        if timeout <= 0:
            raise ValueError("REQUEST_TIMEOUT debe ser un número positivo.")
        log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
            raise ValueError("LOG_LEVEL debe ser DEBUG, INFO, WARNING o ERROR.")
        return cls(
            sonar_url=url,
            sonar_token=token,
            output_dir=Path(os.getenv("OUTPUT_DIR", "./sonarqube_inventory")),
            verify_ssl=_env_bool("VERIFY_SSL", True),
            timeout=timeout,
            log_level=log_level,
        )


@dataclass
class EndpointResult:
    available: bool = False
    supported_parameters: list[str] = field(default_factory=list)
    parameters_known: bool = False
    alternative_used: str | None = None
    reason: str | None = None


class SonarAPIError(Exception):
    """An API failure with no response body or credentials attached."""

    def __init__(self, endpoint: str, status: int | None, reason: str):
        self.endpoint = endpoint
        self.status = status
        self.reason = reason
        suffix = f" (HTTP {status})" if status is not None else ""
        super().__init__(f"{endpoint}{suffix}: {reason}")


class SonarClient:
    def __init__(self, config: Config):
        self.config = config
        self.capabilities: dict[str, EndpointResult] = {}
        self.webservices: dict[str, dict[str, Any]] = {}
        self.context = None
        if urllib.parse.urlparse(config.sonar_url).scheme == "https":
            self.context = ssl.create_default_context()
            if not config.verify_ssl:
                self.context.check_hostname = False
                self.context.verify_mode = ssl.CERT_NONE

    def _url(self, endpoint: str, params: dict[str, Any] | None = None) -> str:
        path = endpoint.lstrip("/")
        url = f"{self.config.sonar_url}/{path}"
        if params:
            encoded = urllib.parse.urlencode(params, doseq=True)
            url = f"{url}?{encoded}"
        return url

    def get(self, endpoint: str, params: dict[str, Any] | None = None) -> Any:
        path = endpoint.lstrip("/")
        request = urllib.request.Request(
            self._url(path, params),
            headers={
                "Authorization": f"Bearer {self.config.sonar_token}",
                "Accept": "application/json",
                "User-Agent": "sonarqube-read-only-inventory/1.0",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.config.timeout, context=self.context
            ) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            # Do not expose server-provided error text: it can contain sensitive data.
            raise SonarAPIError(path, exc.code, "la solicitud no fue aceptada") from None
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as exc:
            # Exception strings from URL libraries may contain the request URL.
            reason = "error de conexión o timeout"
            if isinstance(exc, ssl.SSLError):
                reason = "error de validación TLS"
            raise SonarAPIError(path, None, reason) from None
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise SonarAPIError(path, None, "la respuesta no contiene JSON válido") from None

    def discover_webservices(self) -> None:
        try:
            payload = self.get("api/webservices/list")
        except SonarAPIError as exc:
            self.capabilities["api/webservices/list"] = EndpointResult(
                reason=str(exc)
            )
            LOGGER.warning("No se pudo consultar api/webservices/list: %s", exc)
            return
        services = payload.get("webServices", []) if isinstance(payload, dict) else []
        for service in services if isinstance(services, list) else []:
            if not isinstance(service, dict):
                continue
            for action in service.get("actions", []) or []:
                if not isinstance(action, dict):
                    continue
                path = "/".join(
                    part.strip("/")
                    for part in (service.get("path", ""), action.get("key", ""))
                    if part
                )
                params = action.get("params", []) or []
                self.webservices[path] = {
                    "parameters": {
                        item["key"]
                        for item in params
                        if isinstance(item, dict) and isinstance(item.get("key"), str)
                    },
                    "isInternal": action.get("internal"),
                }
                self.capabilities[path] = EndpointResult(
                    available=True,
                    supported_parameters=sorted(self.webservices[path]["parameters"]),
                    parameters_known=True,
                )
        self.capabilities["api/webservices/list"] = EndpointResult(
            available=True,
            supported_parameters=[],
            parameters_known=True,
        )

    def parameters_for(self, endpoint: str, requested: dict[str, Any]) -> dict[str, Any]:
        metadata = self.webservices.get(endpoint)
        if metadata is None:
            return dict(requested)
        return {key: value for key, value in requested.items() if key in metadata["parameters"]}

    def preferred_endpoint(self, endpoint: str) -> str:
        if endpoint.startswith("api/") and not endpoint.startswith("api/v2/"):
            candidate = "api/v2/" + endpoint[len("api/"):]
            if candidate in self.webservices:
                return candidate
        return endpoint

    def get_preferred(
        self, endpoint: str, params: dict[str, Any] | None = None
    ) -> tuple[Any, str]:
        selected = self.preferred_endpoint(endpoint)
        try:
            result = self.get(selected, self.parameters_for(selected, params or {}))
            self.mark(selected)
        except SonarAPIError as exc:
            self.mark_unavailable(selected, str(exc))
            if selected == endpoint:
                raise
            failed_endpoint = selected
            selected = endpoint
            result = self.get(selected, self.parameters_for(selected, params or {}))
            self.mark(selected)
            self.capabilities[failed_endpoint].alternative_used = selected
        if selected != endpoint:
            self.capabilities.setdefault(endpoint, EndpointResult()).alternative_used = selected
        return result, selected

    def mark(self, endpoint: str, *, alternative: str | None = None, reason: str | None = None) -> None:
        current = self.capabilities.setdefault(endpoint, EndpointResult())
        current.available = True
        current.alternative_used = alternative
        current.reason = reason

    def mark_unavailable(self, endpoint: str, reason: str) -> None:
        current = self.capabilities.setdefault(endpoint, EndpointResult())
        current.available = False
        current.reason = reason

    def fetch_list(
        self,
        endpoint: str,
        collection_names: Iterable[str],
        params: dict[str, Any] | None = None,
    ) -> tuple[list[Any], dict[str, Any]]:
        selected = self.preferred_endpoint(endpoint)
        try:
            result = self._fetch_list(selected, collection_names, params)
        except SonarAPIError as exc:
            self.mark_unavailable(selected, str(exc))
            if selected == endpoint:
                raise
            failed_endpoint = selected
            selected = endpoint
            result = self._fetch_list(selected, collection_names, params)
            self.capabilities[failed_endpoint].alternative_used = selected
        self.mark(selected)
        if selected != endpoint:
            self.capabilities.setdefault(endpoint, EndpointResult()).alternative_used = selected
        return result

    def _fetch_list(
        self,
        endpoint: str,
        collection_names: Iterable[str],
        params: dict[str, Any] | None = None,
    ) -> tuple[list[Any], dict[str, Any]]:
        base_params = dict(params or {})
        metadata = self.webservices.get(endpoint)
        can_page = metadata is None or {"p", "ps"}.issubset(metadata["parameters"])
        items: list[Any] = []
        reported_total: int | None = None
        reported_page_size: int | None = None
        page = 1
        page_count = 0
        while True:
            query = dict(base_params)
            if can_page:
                query.update({"p": page, "ps": PAGE_SIZE})
            query = self.parameters_for(endpoint, query)
            payload = self.get(endpoint, query)
            self.mark(endpoint)
            if not isinstance(payload, dict):
                raise SonarAPIError(endpoint, None, "estructura JSON inesperada")
            collection = next(
                (
                    payload[name]
                    for name in collection_names
                    if isinstance(payload.get(name), list)
                ),
                None,
            )
            if collection is None:
                raise SonarAPIError(endpoint, None, "no se encontró la colección esperada")
            items.extend(collection)
            page_count += 1
            paging = payload.get("paging")
            if isinstance(paging, dict):
                total = paging.get("total")
                if isinstance(total, int):
                    reported_total = total
                current_page = paging.get("pageIndex", page)
                page_size = paging.get("pageSize")
                if isinstance(page_size, int) and page_size > 0:
                    reported_page_size = page_size
                if not isinstance(current_page, int) or not isinstance(page_size, int) or page_size <= 0:
                    break
                if (
                    reported_total is not None
                    and current_page * page_size >= reported_total
                ):
                    break
                if not collection or len(collection) < page_size:
                    break
                page += 1
                continue
            if not can_page or len(collection) < PAGE_SIZE:
                break
            page += 1
        return items, {
            "pages": page_count,
            "reported_total": reported_total,
            "total_pages": (
                (reported_total + reported_page_size - 1) // reported_page_size
                if reported_total is not None and reported_page_size
                else None
            ),
            "reported_page_size": reported_page_size,
            "retrieved": len(items),
            "pagination_reported": reported_total is not None,
        }


class Inventory:
    def __init__(self, client: SonarClient):
        self.client = client
        self.resources: dict[str, dict[str, Any]] = {}

    def _optional_get(
        self, endpoint: str,         params: dict[str, Any] | None = None
    ) -> dict[str, Any] | None:
        try:
            result, _ = self.client.get_preferred(endpoint, params)
            return result if isinstance(result, dict) else {"value": result}
        except SonarAPIError as exc:
            self.client.mark_unavailable(endpoint, str(exc))
            LOGGER.warning("No se pudo obtener %s: %s", endpoint, exc)
            return None

    def _optional_list(
        self,
        resource: str,
        endpoint: str,
        collection_names: Iterable[str],
        params: dict[str, Any] | None = None,
    ) -> list[Any]:
        try:
            items, stats = self.client.fetch_list(endpoint, collection_names, params)
            self.resources[resource] = {
                "status": "available",
                **stats,
            }
            return items
        except SonarAPIError as exc:
            self.client.mark_unavailable(endpoint, str(exc))
            self.resources[resource] = {
                "status": "not_available",
                "pages": 0,
                "reported_total": None,
                "total_pages": None,
                "reported_page_size": None,
                "retrieved": 0,
                "reason": str(exc),
            }
            LOGGER.warning("No se pudo recolectar %s: %s", resource, exc)
            return []

    def collect(self) -> dict[str, Any]:
        version_result: dict[str, Any] = {}
        try:
            version_result = {"version": self.client.get("api/server/version")}
            self.client.mark("api/server/version")
        except SonarAPIError as exc:
            self.client.mark_unavailable("api/server/version", str(exc))
            LOGGER.warning("No se pudo obtener la versión: %s", exc)

        status = self._optional_get("api/system/status")
        self.client.discover_webservices()
        authentication = self._optional_get("api/authentication/validate")
        current_user = self._optional_get("api/users/current")
        plugins, plugin_stats = self._try_simple_list(
            "api/plugins/installed", ("plugins",)
        )
        languages, language_stats = self._try_simple_list(
            "api/languages/list", ("languages",)
        )
        rules_catalog = self._optional_list(
            "rules_catalog", "api/rules/search", ("rules",)
        )
        permissions = self._optional_list(
            "global_permissions",
            "api/permissions/search_global",
            ("permissions",),
        )
        if "global_permissions" not in self.resources:
            self.resources["global_permissions"] = self._resource_stats(
                self.client.capabilities.get("api/permissions/search_global"), permissions
            )
        if "plugins" not in self.resources:
            self.resources["plugins"] = plugin_stats
        if "languages" not in self.resources:
            self.resources["languages"] = language_stats

        profiles = self._optional_list(
            "quality_profiles", "api/qualityprofiles/search", ("profiles",)
        )
        profile_details: list[dict[str, Any]] = []
        rules_by_profile: dict[str, list[dict[str, Any]]] = {}
        for profile in profiles:
            if not isinstance(profile, dict) or not profile.get("key"):
                continue
            key = profile["key"]
            detail = dict(profile)
            detail["profile_classification"] = self._profile_classification(profile)
            inheritance = self._optional_get(
                "api/qualityprofiles/inheritance", {"profileKey": key}
            )
            detail["inheritance_api"] = inheritance
            changelog, stats = self._profile_changelog(key)
            detail["changelog"] = changelog
            detail["changelog_retrieval"] = stats
            active_rules, rule_stats = self._profile_rules(key)
            detail["active_rules"] = active_rules
            detail["active_rules_retrieval"] = rule_stats
            if rule_stats.get("status") == "available":
                rules_by_profile[key] = active_rules
            profile_details.append(detail)
        inferred_profile_diffs = self._compare_profiles(profile_details, rules_by_profile)
        comparisons_performed = sum(
            1
            for profile in profile_details
            if profile.get("key") in rules_by_profile
            if profile.get("active_rules_retrieval", {}).get("status") == "available"
            and profile.get("inheritance_api")
            and self._parent_key(profile["inheritance_api"], {
                item["key"]: item for item in profile_details if item.get("key")
            })[0] in rules_by_profile
        )
        self.resources["profile_rule_differences_inferred"] = {
            "status": "available" if comparisons_performed else "not_available",
            "pages": 0,
            "reported_total": None,
            "total_pages": None,
            "reported_page_size": None,
            "retrieved": len(inferred_profile_diffs),
            "comparisons_performed": comparisons_performed,
            "note": (
                "Inferido comparando reglas activas con un perfil padre explícito "
                "o un único ancestro reportado."
            ),
        }

        gates = self._optional_list(
            "quality_gates", "api/qualitygates/list", ("qualitygates",)
        )
        gate_details: list[dict[str, Any]] = []
        for gate in gates:
            if not isinstance(gate, dict) or not gate.get("id"):
                continue
            detail = dict(gate)
            shown = self._optional_get("api/qualitygates/show", {"id": gate["id"]})
            detail["details_api"] = shown
            gate_details.append(detail)

        projects = self._optional_list(
            "projects",
            "api/projects/search",
            ("components", "projects"),
            {"qualifiers": "TRK"},
        )
        associations: list[dict[str, Any]] = []
        for project in projects:
            if not isinstance(project, dict) or not project.get("key"):
                continue
            project_key = project["key"]
            association: dict[str, Any] = {
                "project": project,
                "quality_profiles_api": None,
                "quality_gate_api": None,
            }
            association["quality_profiles_api"] = self._optional_get(
                "api/qualityprofiles/search", {"project": project_key}
            )
            association["quality_gate_api"] = self._optional_get(
                "api/qualitygates/get_by_project", {"project": project_key}
            )
            associations.append(association)

        edition = None
        if status:
            license_info = status.get("license")
            edition = status.get("edition")
            if edition is None and isinstance(license_info, dict):
                edition = license_info.get("edition")
        instance = {
            **version_result,
            "url": self.client.config.sonar_url,
            "status": status,
            "edition": edition,
            "plugins": plugins,
            "languages_or_analyzers": languages,
            "authenticated_user": self._authenticated_identity(authentication, current_user),
            "global_permissions": permissions,
        }

        return {
            "schema_version": "1.0",
            "extracted_at_utc": datetime.now(UTC).isoformat(),
            "source": "SonarQube Server Web API",
            "read_only": True,
            "instance": instance,
            "api_v2_endpoints_discovered": sorted(
                endpoint
                for endpoint in self.client.webservices
                if endpoint.startswith("api/v2/")
            ),
            "capabilities": {
                endpoint: {
                    "available": capability.available,
                    "supported_parameters": capability.supported_parameters,
                    "parameters_known": capability.parameters_known,
                    "alternative_used": capability.alternative_used,
                    "reason": capability.reason,
                }
                for endpoint, capability in sorted(self.client.capabilities.items())
            },
            "resources": self.resources,
            "quality_profiles": profile_details,
            "rules_catalog": rules_catalog,
            "quality_profile_differences": {
                "data_origin": "inferred_by_comparison",
                "items": inferred_profile_diffs,
            },
            "quality_gates": gate_details,
            "project_associations": {
                "data_origin": "direct_api_responses",
                "items": associations,
            },
            "data_origin_guide": {
                "direct_api_responses": "Campos terminados en _api y registros no transformados obtenidos de la Web API.",
                "inferred_by_comparison": "Diferencias derivadas al comparar reglas activas del perfil padre y el perfil hijo.",
                "not_available": "No se recibieron datos; consulte capabilities y resources para el motivo.",
            },
        }

    def _try_simple_list(
        self, endpoint: str, collection_names: tuple[str, ...]
    ) -> tuple[list[Any], dict[str, Any]]:
        items = self._optional_list(endpoint, endpoint, collection_names)
        return items, self.resources.get(endpoint, self._resource_stats(
            self.client.capabilities.get(endpoint), items
        ))

    @staticmethod
    def _resource_stats(
        capability: EndpointResult | None, items: list[Any]
    ) -> dict[str, Any]:
        available = bool(capability and capability.available)
        return {
            "status": "available" if available else "not_available",
            "pages": 0,
            "reported_total": None,
            "total_pages": None,
            "reported_page_size": None,
            "retrieved": len(items),
            "pagination_reported": False,
            **({"reason": capability.reason} if capability and capability.reason else {}),
        }

    @staticmethod
    def _authenticated_identity(
        validation: dict[str, Any] | None,
        user: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        identity: dict[str, Any] = {}
        if validation:
            identity["validation_api"] = validation
        if user:
            identity["user_api"] = user
        return identity or None

    @staticmethod
    def _profile_classification(profile: dict[str, Any]) -> dict[str, Any]:
        built_in = profile.get("isBuiltIn")
        if isinstance(built_in, bool):
            return {
                "value": "built_in" if built_in else "custom",
                "data_origin": "direct_api_field",
                "field": "isBuiltIn",
            }
        return {
            "value": "not_available",
            "data_origin": "not_available",
            "reason": "La respuesta del perfil no incluye el campo isBuiltIn.",
        }

    def _profile_rules(self, profile_key: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        return self._list_first_endpoint(
            ("api/rules/search",),
            ("rules",),
            {"activation": "true", "qprofile": profile_key},
        )

    def _profile_changelog(
        self, profile_key: str
    ) -> tuple[list[Any] | None, dict[str, Any]]:
        events, stats = self._list_first_endpoint(
            ("api/qualityprofiles/changelog",),
            ("events",),
            {"profileKey": profile_key},
        )
        return (events if stats.get("status") == "available" else None), stats

    def _list_first_endpoint(
        self,
        endpoints: tuple[str, ...],
        collections: tuple[str, ...],
        params: dict[str, Any],
    ) -> tuple[list[Any], dict[str, Any]]:
        last_reason = "no se encontró un endpoint compatible"
        for endpoint in endpoints:
            try:
                items, stats = self.client.fetch_list(endpoint, collections, params)
                stats["status"] = "available"
                return items, stats
            except SonarAPIError as exc:
                last_reason = str(exc)
                self.client.mark_unavailable(endpoint, last_reason)
        return [], {
            "status": "not_available",
            "pages": 0,
            "reported_total": None,
            "total_pages": None,
            "reported_page_size": None,
            "retrieved": 0,
            "reason": last_reason,
        }

    @staticmethod
    def _compare_profiles(
        profiles: list[dict[str, Any]],
        rules_by_profile: dict[str, list[dict[str, Any]]],
    ) -> list[dict[str, Any]]:
        by_key = {profile["key"]: profile for profile in profiles if profile.get("key")}
        differences = []
        for profile in profiles:
            key = profile.get("key")
            inheritance = profile.get("inheritance_api")
            if not key or not isinstance(inheritance, dict):
                continue
            parent_key, comparison_basis = Inventory._parent_key(inheritance, by_key)
            if (
                not parent_key
                or key not in rules_by_profile
                or parent_key not in rules_by_profile
            ):
                continue
            child_rules = rules_by_profile.get(key, [])
            parent_rules = rules_by_profile.get(parent_key, [])
            parent_map = {r.get("key"): r for r in parent_rules if isinstance(r, dict) and r.get("key")}
            child_map = {r.get("key"): r for r in child_rules if isinstance(r, dict) and r.get("key")}
            entries = []
            for rule_key in sorted(child_map.keys() - parent_map.keys()):
                entries.append({
                    "rule_key": rule_key,
                    "change": "added_or_inherited_difference",
                    "child": child_map[rule_key],
                    "parent": None,
                })
            for rule_key in sorted(parent_map.keys() - child_map.keys()):
                entries.append({
                    "rule_key": rule_key,
                    "change": "deactivated_or_not_inherited",
                    "child": None,
                    "parent": parent_map[rule_key],
                })
            for rule_key in sorted(child_map.keys() & parent_map.keys()):
                parent_rule, child_rule = parent_map[rule_key], child_map[rule_key]
                changed = {}
                for field_name in ("severity", "params"):
                    parent_value = Inventory._normalize_rule_field(parent_rule, field_name)
                    child_value = Inventory._normalize_rule_field(child_rule, field_name)
                    if parent_value != child_value and (
                        parent_value is not None or child_value is not None
                    ):
                        changed[field_name] = {
                            "parent": parent_value,
                            "child": child_value,
                        }
                if changed:
                    entries.append({
                        "rule_key": rule_key,
                        "change": "modified",
                        "fields": changed,
                    })
            if entries:
                differences.append({
                    "profile_key": key,
                    "comparison_profile_key": parent_key,
                    "comparison_basis": comparison_basis,
                    "items": entries,
                })
        return differences

    @staticmethod
    def _parent_key(
        inheritance: dict[str, Any], profiles: dict[str, Any]
    ) -> tuple[str | None, str | None]:
        # An unordered or multi-level ancestor list is not enough to identify
        # the direct parent, so compare only an explicit parent or one ancestor.
        candidates = []
        for name in ("parent", "parentProfile", "parentProfileKey", "parentKey"):
            value = inheritance.get(name)
            if isinstance(value, dict):
                value = value.get("key")
            if isinstance(value, str):
                candidates.append(value)
        explicit = next((candidate for candidate in candidates if candidate in profiles), None)
        if explicit:
            return explicit, "explicit_parent_reported_by_api"
        ancestors = inheritance.get("ancestors")
        if isinstance(ancestors, list) and len(ancestors) == 1:
            ancestor = ancestors[0]
            key = ancestor.get("key") if isinstance(ancestor, dict) else ancestor
            if isinstance(key, str) and key in profiles:
                return key, "single_reported_ancestor_not_confirmed_as_direct_parent"
        return None, None

    @staticmethod
    def _normalize_rule_field(rule: dict[str, Any], field_name: str) -> Any:
        activation = rule.get("actives")
        if isinstance(activation, list):
            for active in activation:
                if isinstance(active, dict):
                    if field_name == "severity" and "severity" in active:
                        return active["severity"]
                    if field_name == "params":
                        params = active.get("params")
                        if isinstance(params, list):
                            return sorted(
                                (p.get("key"), p.get("value"))
                                for p in params
                                if isinstance(p, dict)
                            )
        if field_name in rule:
            value = rule[field_name]
            if field_name == "params" and isinstance(value, list):
                return sorted(
                    (p.get("key"), p.get("value"))
                    for p in value if isinstance(p, dict)
                )
            return value
        return None


def main() -> int:
    try:
        config = Config.from_env()
    except ValueError as exc:
        print(f"Error de configuración: {exc}", file=sys.stderr)
        return 2
    logging.basicConfig(
        level=getattr(logging, config.log_level),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    try:
        inventory = Inventory(SonarClient(config)).collect()
        config.output_dir.mkdir(parents=True, exist_ok=True)
        output_path = config.output_dir / "sonarqube_inventory.json"
        output_path.write_text(
            json.dumps(inventory, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except SonarAPIError as exc:
        LOGGER.error("Error al consultar SonarQube: %s", exc)
        return 1
    except OSError as exc:
        LOGGER.error("No se pudo escribir el inventario (%s).", exc.__class__.__name__)
        return 1
    LOGGER.info("Inventario guardado en %s", output_path.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

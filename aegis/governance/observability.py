"""OpenTelemetry Reasoning Trace Observability and Google Cloud Trace Exporter.

Architectural Rule:
THE OBSERVABILITY TRACE IS NOT A DEBUG FEATURE. IT IS THE PRODUCT.
A credential is only trustworthy if you can audit exactly how it was awarded.
Every credential Aegis issues carries the OpenTelemetry trace ID of the
reasoning chain that produced it, plus a signed tamper-evident audit trail.
"""

from contextlib import contextmanager
import logging
import os
from typing import Any, Dict, Generator, Optional
import uuid

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)
from opentelemetry.trace import Tracer

from aegis.config import settings

logger = logging.getLogger("aegis.governance.observability")

_tracer_initialized = False
_tracer: Optional[Tracer] = None


def setup_telemetry() -> Tracer:
    """Initializes OpenTelemetry TracerProvider with Cloud Trace or local console exporter."""
    global _tracer_initialized, _tracer

    if _tracer_initialized and _tracer is not None:
        return _tracer

    provider = TracerProvider()

    if settings.export_traces:
        try:
            # Lazy import GCP Cloud Trace exporter
            from opentelemetry.exporter.gcp_trace import CloudTraceSpanExporter

            cloud_exporter = CloudTraceSpanExporter(project_id=settings.gcp_project)
            provider.add_span_processor(BatchSpanProcessor(cloud_exporter))
            logger.info("OpenTelemetry initialized with Google Cloud Trace exporter (project=%s)", settings.gcp_project)
        except Exception as exc:
            logger.warning("Failed to initialize Google Cloud Trace exporter: %s; falling back to in-memory/console", exc)
            provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
    else:
        # Local development / zero-cloud execution: simple processor
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))

    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer("aegis.fleet", "1.0.0")
    _tracer_initialized = True
    return _tracer


def get_tracer() -> Tracer:
    """Returns the configured OpenTelemetry tracer."""
    global _tracer
    if _tracer is None:
        return setup_telemetry()
    return _tracer


def current_trace_id() -> str:
    """Returns the 32-character hexadecimal trace ID of the active span, or generates a fresh one."""
    current_span = trace.get_current_span()
    ctx = current_span.get_span_context()
    if ctx and ctx.is_valid and ctx.trace_id != 0:
        return f"{ctx.trace_id:032x}"
    return uuid.uuid4().hex


@contextmanager
def span(name: str, attributes: Optional[Dict[str, Any]] = None) -> Generator[trace.Span, None, None]:
    """Context manager for tracing agent execution, tool invocations, and state transitions."""
    tracer = get_tracer()
    with tracer.start_as_current_span(name) as active_span:
        if attributes:
            for k, v in attributes.items():
                if v is not None:
                    active_span.set_attribute(k, str(v) if isinstance(v, (dict, list, set)) else v)
        yield active_span


def cloud_trace_url(trace_id: str, project_id: Optional[str] = None) -> str:
    """Constructs a direct Google Cloud Console deep link for an OpenTelemetry trace ID."""
    proj = project_id or settings.gcp_project
    return f"https://console.cloud.google.com/traces/traces/{trace_id}?project={proj}"

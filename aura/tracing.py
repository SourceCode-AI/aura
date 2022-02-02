try:
    from opentelemetry import trace
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    from opentelemetry.sdk.resources import SERVICE_NAME, Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    trace.set_tracer_provider(
        TracerProvider(
            resource=Resource.create({SERVICE_NAME: "aura"})
        )
    )

    jaeger_exporter = JaegerExporter(
        udp_split_oversized_batches=True
    )
    trace.get_tracer_provider().add_span_processor(
        BatchSpanProcessor(jaeger_exporter)
    )

    tracer = trace.get_tracer(__name__)
except ImportError:
    from unittest.mock import MagicMock

    tracer = MagicMock()

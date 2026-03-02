"""Kafka的AlertReporter实现"""
from dataclasses import dataclass, asdict
from failslow.task.alert_reporter.interface import BufferedAlertReporterBase, AlertBase
from queue import Queue
import json
from failslow.util.logging_utils import get_default_logger


logger = get_default_logger(__name__)


@dataclass
class KafkaAlertReporterConfig:
    """Kafka alert reporter configuration."""
    bootstrap_servers: str = ""
    topic: str = ""
    client_id: str = ""
    buffer_size: int = 1000

class KafkaAlertReporter(BufferedAlertReporterBase):
    """Kafka alert reporter implementation."""

    def __init__(self, config: dict) -> None:
        super().__init__()
        self.config: KafkaAlertReporterConfig = KafkaAlertReporterConfig(**config)
        try:
        # Import KafkaProducer here to avoid unnecessary dependency if not used
            from kafka import KafkaProducer

            self.producer = KafkaProducer(
                bootstrap_servers=self.config.bootstrap_servers,
                client_id=config.client_id,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            )
        except ImportError:
            raise ImportError("kafka-python package is required for KafkaAlertReporter. Please install it via 'pip install kafka-python'.")
        except Exception as e:
            logger.error(f"Failed to initialize KafkaAlertReporter: {e}")
            raise
        
        logger.info(
            f"Initialized KafkaAlertReporter with topic: %s "
            f"and bootstrap_servers: %s",
            self.config.topic,
            self.config.bootstrap_servers,
        )
        self.alert_queue = Queue(maxsize=self.config.buffer_size)

    def report_alert(self, alert: dict) -> None:
        """Send an alert to the configured Kafka topic."""
        alert_data = alert
        self.producer.send(self.config.topic, value=alert_data)
        self.producer.flush()
        logger.info(f"Alert sent to Kafka topic {self.config.topic}: {alert_data}")

    def get_all_alerts(self):
        return list(self.alert_queue.queue)




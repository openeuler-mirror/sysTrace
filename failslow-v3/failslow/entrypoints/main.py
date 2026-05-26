"""
Main entry point for the FailSlow v3 application.
"""
import argparse
import logging
from pathlib import Path

from ..infrastructure.framework.registration import (
    ComponentFactory,
    DataSourceRegistry,
    PreprocessorRegistry,
    DetectorRegistry,
    ReporterRegistry,
    MetricExtractorRegistry,
    DataSinkRegistry,
)
from ..infrastructure import components
from ..infrastructure.framework.configuration import ConfigLoader
from ..application.app import Application
from ..util.logging import setup_logging


def main():
    """Main application function."""
    parser = argparse.ArgumentParser(
        description="FailSlow v3 异常检测框架",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s --config /etc/systrace/config/config.slow_calc.json

  通过 systemd 运行:
  systemctl start systrace-failslow
        """
    )
    parser.add_argument(
        "--config",
        type=str,
        required=True,
        help="Path to the JSON configuration file."
    )
    args = parser.parse_args()

    config_path = Path(args.config)

    source_factory = ComponentFactory(DataSourceRegistry)
    preprocessor_factory = ComponentFactory(PreprocessorRegistry)
    detector_factory = ComponentFactory(DetectorRegistry)
    reporter_factory = ComponentFactory(ReporterRegistry)
    metric_extractor_factory = ComponentFactory(MetricExtractorRegistry)
    data_sink_factory = ComponentFactory(DataSinkRegistry)

    config_loader = ConfigLoader(
        source_factory=source_factory,
        preprocessor_factory=preprocessor_factory,
        detector_factory=detector_factory,
        reporter_factory=reporter_factory,
        metric_extractor_factory=metric_extractor_factory,
        data_sink_factory=data_sink_factory,
    )

    try:
        config = config_loader.load_from_file(config_path)
        setup_logging(config.logging.get("level", "INFO"))

        app = Application(config)
        app.start()

    except Exception as e:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s")
        logging.error(f"An error occurred during application startup: {e}", exc_info=True)
        exit(1)


if __name__ == "__main__":
    main()

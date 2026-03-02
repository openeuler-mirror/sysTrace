"""
Implementation of a data source that reads step-level CSV files for degradation detection.
"""
import glob
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import StringIO
from typing import Dict, Iterator, List, Optional

import pandas as pd

from failslow.domain.models import KernelType, StepMetrics
from failslow.infrastructure.components.sources.degradation_step_csv.schema import (
    DegradationStepCsvParams,
)
from failslow.infrastructure.framework.registration import DataSourceRegistry

logger = logging.getLogger(__name__)

DEGRADATION_COLUMNS = ["step_id", "step_start_time", "step_end_time", "step_exec_time"]


class DegradationStepCsvDataSource(DataSourceRegistry):
    """
    A data source that reads step-level CSV files and converts them to StepMetrics
    with synthetic kernel information for degradation detection.

    Expected CSV columns: step_id, step_start_time, step_end_time, step_exec_time

    Supports both batch mode (read all files at once via read()) and
    incremental mode (read only new data via read_incremental()).
    """

    COMPONENT_NAME = "degradation_step_csv"

    def __init__(self, params: Optional[DegradationStepCsvParams] = None, max_workers: int = 1, **kwargs):
        if isinstance(params, DegradationStepCsvParams):
            self._params = params
        else:
            self._params = DegradationStepCsvParams(
                directory_path=kwargs.get("directory_path", "."),
                file_pattern=kwargs.get("file_pattern", "training_step_time_*.csv"),
                max_workers=kwargs.get("max_workers", max_workers),
            )
        self._file_offsets: Dict[str, int] = {}
        self._file_headers: Dict[str, str] = {}

    def connect(self) -> None:
        pass

    def disconnect(self) -> None:
        pass

    def is_connected(self) -> bool:
        return True

    def read(self) -> Iterator[StepMetrics]:
        """
        Read step-level CSV files and yield StepMetrics.

        Converts step-level data to kernel-level structure:
        - t_exec_ns = step_exec_time
        - start_time_ns = step_start_time
        - end_time_ns = step_end_time
        """
        directory = self._params.directory_path
        pattern = self._params.file_pattern

        if not os.path.isdir(directory):
            logger.error("Directory not found: %s", directory)
            return

        search_path = os.path.join(directory, pattern)
        csv_files = sorted(glob.glob(search_path))

        if not csv_files:
            logger.warning("No CSV files found matching %s", search_path)
            return

        if self._params.max_workers <= 1:
            for csv_file in csv_files:
                for metrics in self._parse_single_file(csv_file):
                    yield metrics
        else:
            with ThreadPoolExecutor(max_workers=self._params.max_workers) as executor:
                futures = {
                    executor.submit(self._parse_single_file, f): f
                    for f in csv_files
                }
                for future in as_completed(futures):
                    try:
                        for metrics in future.result():
                            yield metrics
                    except Exception:
                        csv_file = futures[future]
                        logger.warning("Error reading file %s: %s", csv_file, future.exception())
                        if self._params.directory_path:
                            raise

    def _parse_single_file(self, csv_file: str) -> List[StepMetrics]:
        """
        Parse a single degradation CSV file and return list of StepMetrics.

        Expected CSV columns: step_id, step_start_time, step_end_time, step_exec_time
        """
        rank_id = self._extract_rank_from_filename(csv_file)
        node_ip = self._extract_ip_from_filename(csv_file)
        metrics_list: List[StepMetrics] = []

        try:
            df = pd.read_csv(csv_file)
            if df.empty:
                logger.warning("Empty CSV file: %s", csv_file)
                return metrics_list

            required_columns = ["step_id", "step_start_time", "step_end_time", "step_exec_time"]
            missing = [col for col in required_columns if col not in df.columns]
            if missing:
                logger.warning(
                    "CSV file %s missing required columns: %s", csv_file, missing
                )
                return metrics_list

            for _, row in df.iterrows():
                step_id = int(row["step_id"])
                step_start = int(row["step_start_time"])
                step_end = int(row["step_end_time"])
                step_exec = float(row["step_exec_time"])

                kernel = KernelType(
                    name="training_step",
                    t1_ns=step_start,
                    t2_ns=step_end,
                    t_delta_ns=step_end - step_start,
                    t_exec_ns=step_exec,
                    t3_ns=0,
                    t4_ns=0,
                )

                metrics = StepMetrics(
                    start_time_ns=step_start,
                    end_time_ns=step_end,
                    step=step_id,
                    rank_id=rank_id,
                    local_rank_id=0,
                    node_ip=node_ip,
                    node_port=0,
                    kernels=[kernel],
                )

                metrics_list.append(metrics)

        except Exception as e:
            logger.warning("Error reading file %s: %s", csv_file, e)
            if self._params.directory_path:
                raise

        return metrics_list

    def read_incremental(self) -> List[StepMetrics]:
        """
        Incrementally read new data from CSV files since last call.

        Tracks byte offsets per file and only reads newly appended data.
        Each row is a self-contained step record (no partial grouping needed).

        Returns:
            List of new StepMetrics parsed from newly appended CSV data.
        """
        directory = self._params.directory_path
        pattern = self._params.file_pattern

        if not os.path.isdir(directory):
            logger.warning("Data directory not found: %s", directory)
            return []

        search_path = os.path.join(directory, pattern)
        csv_files = sorted(glob.glob(search_path))
        if not csv_files:
            return []

        all_new_metrics: List[StepMetrics] = []

        for csv_file in csv_files:
            filename = os.path.basename(csv_file)
            try:
                current_size = os.path.getsize(csv_file)
            except OSError:
                continue

            prev_offset = self._file_offsets.get(filename, 0)

            if current_size <= prev_offset:
                if current_size < prev_offset:
                    logger.info(
                        "File %s shrank (%d -> %d), resetting offset",
                        filename,
                        prev_offset,
                        current_size,
                    )
                    self._file_offsets[filename] = 0
                    self._file_headers.pop(filename, None)
                continue

            if prev_offset == 0:
                new_metrics = self._read_full_file_incremental(filename, csv_file)
            else:
                new_metrics = self._read_appended_data_incremental(
                    filename, csv_file, prev_offset
                )

            all_new_metrics.extend(new_metrics)
            self._file_offsets[filename] = current_size

        return all_new_metrics

    def _read_full_file_incremental(
        self, filename: str, filepath: str
    ) -> List[StepMetrics]:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                header_line = f.readline()
                self._file_headers[filename] = header_line
            df = pd.read_csv(filepath)
            if df.empty:
                return []
        except Exception as e:
            logger.warning("Failed to read file %s: %s", filepath, e)
            return []

        return self._df_to_step_metrics(df, filepath)

    def _read_appended_data_incremental(
        self, filename: str, filepath: str, prev_offset: int
    ) -> List[StepMetrics]:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                f.seek(prev_offset)
                new_content = f.read()
        except Exception as e:
            logger.warning(
                "Failed to read appended data from %s: %s", filepath, e
            )
            return []

        if not new_content.strip():
            return []

        header_line = self._file_headers.get(filename, "")
        if not header_line:
            return []

        try:
            content = header_line + new_content
            df = pd.read_csv(StringIO(content))
            if df.empty:
                return []
        except Exception as e:
            logger.warning(
                "Failed to parse appended data from %s: %s", filepath, e
            )
            return []

        return self._df_to_step_metrics(df, filepath)

    def _df_to_step_metrics(
        self, df: pd.DataFrame, filepath: str
    ) -> List[StepMetrics]:
        required_columns = DEGRADATION_COLUMNS
        missing = [col for col in required_columns if col not in df.columns]
        if missing:
            logger.warning(
                "CSV file %s missing required columns: %s", filepath, missing
            )
            return []

        rank_id = self._extract_rank_from_filename(filepath)
        node_ip = self._extract_ip_from_filename(filepath)
        metrics = []

        for _, row in df.iterrows():
            step_id = int(row["step_id"])
            step_start = int(row["step_start_time"])
            step_end = int(row["step_end_time"])
            step_exec = float(row["step_exec_time"])

            kernel = KernelType(
                name="training_step",
                t1_ns=step_start,
                t2_ns=step_end,
                t_delta_ns=step_end - step_start,
                t_exec_ns=step_exec,
                t3_ns=0,
                t4_ns=0,
            )

            sm = StepMetrics(
                start_time_ns=step_start,
                end_time_ns=step_end,
                step=step_id,
                rank_id=rank_id,
                local_rank_id=0,
                node_ip=node_ip,
                node_port=0,
                kernels=[kernel],
            )
            metrics.append(sm)

        return metrics

    @staticmethod
    def is_degradation_format(filepath: str) -> bool:
        """
        Check if a CSV file has degradation detection format columns.

        Returns True if the file contains the expected degradation columns:
        step_id, step_start_time, step_end_time, step_exec_time.
        """
        try:
            df = pd.read_csv(filepath, nrows=0)
            columns = set(df.columns)
            required = set(DEGRADATION_COLUMNS)
            return required.issubset(columns)
        except Exception:
            return False

    def _extract_rank_from_filename(self, filepath: str) -> int:
        """Extract rank ID from filename like training-step-time-7.242.102.253-0.csv"""
        filename = os.path.basename(filepath)
        # training-step-time-IP-rank.csv -> split by '-' and get last part without .csv
        parts = filename.replace(".csv", "").split("-")
        if len(parts) >= 5:
            try:
                return int(parts[-1])
            except ValueError:
                pass
        return 0

    def _extract_ip_from_filename(self, filepath: str) -> str:
        """Extract IP from filename like training-step-time-7.242.102.253-0.csv"""
        filename = os.path.basename(filepath)
        # training-step-time-IP-rank.csv -> IP is in the middle
        parts = filename.replace(".csv", "").split("-")
        if len(parts) >= 5:
            # parts: ['training', 'step', 'time', '7.242.102.253', '0']
            ip = parts[3]
            if "." in ip:
                return ip
        return "0.0.0.0"
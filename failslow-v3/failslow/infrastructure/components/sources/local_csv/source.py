"""
Implementation of a data source that reads from a directory of local CSV files.
"""
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterator, List, Optional

import numpy as np
import pandas as pd

from failslow.domain.models import StepMetrics
from failslow.infrastructure.framework.registration import DataSourceRegistry

from .csv_parsers import (
    DataFormat,
    HCCLDataParser,
    NCCLDataParser,
    build_step_metrics,
    detect_format_by_columns,
    detect_format_by_file,
    detect_format_by_filename,
    extract_ip_from_filename,
    extract_rank_from_filename,
    is_standard_csv_filename,
)
from .schema import LocalCsvParams

logger = logging.getLogger(__name__)


class LocalCsvDataSource(DataSourceRegistry):
    """
    A data source that discovers, parses, and streams performance data from a
    directory of local CSV files.

    Supports both batch mode (read all files at once via read()) and
    incremental mode (read only new data via read_incremental()).
    """

    COMPONENT_NAME = "local_csv"

    def __init__(
        self,
        directory_path: str,
        format: str = "auto",
        strict_mode: bool = False,
        max_workers: int = 1,
        params: Optional[LocalCsvParams] = None,
    ):
        if isinstance(directory_path, LocalCsvParams):
            params = directory_path
        if params is not None:
            self._params = params
        else:
            params_dict = {
                "directory_path": directory_path,
                "format": format,
                "strict_mode": strict_mode,
                "max_workers": max_workers,
            }
            self._params = LocalCsvParams(**params_dict)

        self._file_offsets: Dict[str, int] = {}
        self._file_headers: Dict[str, str] = {}
        self._file_formats: Dict[str, DataFormat] = {}
        self._hccl_partial_ids: Dict[str, Dict[int, dict]] = {}

    def connect(self) -> None:
        pass

    def disconnect(self) -> None:
        pass

    def is_connected(self) -> bool:
        return True

    def read(self) -> Iterator[StepMetrics]:
        """
        Read and parse CSV files from the directory, yielding StepMetrics per rank.

        Yields:
            StepMetrics for each rank with parsed kernel information.
        """
        directory = self._params.directory_path

        if not os.path.isdir(directory):
            logger.error("Directory not found: %s", directory)
            return

        csv_files = sorted([f for f in os.listdir(directory) if f.endswith(".csv")])
        if not csv_files:
            logger.warning("No CSV files found in directory: %s", directory)
            return

        detected_format = self._detect_format_from_directory(directory)

        if self._params.format != "auto":
            data_format = DataFormat.HCCL if self._params.format == "hccl" else DataFormat.NCCL
        elif detected_format != DataFormat.UNKNOWN:
            data_format = detected_format
        else:
            data_format = None

        parser = None
        if data_format is not None:
            parser = self._get_parser_for_format(data_format)

        valid_csv_files = [f for f in csv_files if is_standard_csv_filename(f)]

        if self._params.max_workers <= 1:
            rank_data = self._parse_files_serial(valid_csv_files, directory, parser, data_format)
        else:
            rank_data = self._parse_files_parallel(valid_csv_files, directory, parser, data_format)

        all_steps = []
        for rank_id in sorted(rank_data.keys()):
            for record in rank_data[rank_id]:
                if record["data_format"] == DataFormat.HCCL:
                    record["step"] = 0
                metrics = build_step_metrics(rank_id, record, record["data_format"])
                if metrics is not None:
                    all_steps.append(metrics)

        for step in all_steps:
            yield step

    def _parse_files_serial(
        self,
        csv_files: List[str],
        directory: str,
        parser,
        data_format,
    ) -> Dict[int, List[Dict]]:
        """Parse CSV files one by one in the current thread."""
        rank_data: Dict[int, List[Dict]] = {}
        for csv_file in csv_files:
            result = self._parse_single_file(csv_file, directory, parser, data_format)
            if result is not None:
                rank, records = result
                rank_data.setdefault(rank, []).extend(records)
        return rank_data

    def _parse_files_parallel(
        self,
        csv_files: List[str],
        directory: str,
        parser,
        data_format,
    ) -> Dict[int, List[Dict]]:
        """Parse CSV files in parallel using a thread pool."""
        rank_data: Dict[int, List[Dict]] = {}
        with ThreadPoolExecutor(max_workers=self._params.max_workers) as executor:
            futures = {
                executor.submit(self._parse_single_file, f, directory, parser, data_format): f
                for f in csv_files
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception:
                    csv_file = futures[future]
                    logger.warning("Error parsing file %s: %s", csv_file, future.exception())
                    if self._params.strict_mode:
                        raise
                    continue
                if result is not None:
                    rank, records = result
                    rank_data.setdefault(rank, []).extend(records)
        return rank_data

    def _parse_single_file(
        self,
        csv_file: str,
        directory: str,
        parser,
        data_format,
    ):
        """
        Parse a single CSV file and return (rank_id, records) or None on error.

        Each record is a dict with keys: op_name, t1, t2, t3, t4, step, ip, data_format.
        """
        filepath = os.path.join(directory, csv_file)
        rank = extract_rank_from_filename(csv_file)
        ip_addr = extract_ip_from_filename(csv_file)

        try:
            df = pd.read_csv(filepath)
            if df.empty:
                logger.warning("Empty CSV file: %s", csv_file)
                return None

            file_parser = parser
            file_format = data_format

            if file_parser is None:
                file_format = detect_format_by_columns(df)
                if file_format == DataFormat.UNKNOWN:
                    logger.warning("Could not detect format for file: %s", csv_file)
                    return None
                file_parser = self._get_parser_for_format(file_format)

            parsed_df = file_parser(df, rank)

            if parsed_df.empty:
                return None

            records = []
            if "step" in parsed_df.columns:
                for _, row in parsed_df.iterrows():
                    records.append({
                        "op_name": row["op_name"],
                        "t1": row["t1"],
                        "t2": row["t2"],
                        "t3": row["t3"],
                        "t4": row["t4"],
                        "step": int(row["step"]) if pd.notna(row["step"]) else 0,
                        "ip": ip_addr,
                        "data_format": file_format,
                    })
            else:
                for _, row in parsed_df.iterrows():
                    records.append({
                        "op_name": row["op_name"],
                        "t1": row["t1"],
                        "t2": row["t2"],
                        "t3": row["t3"],
                        "t4": row["t4"],
                        "step": 0,
                        "ip": ip_addr,
                        "data_format": file_format,
                    })

            return rank, records

        except pd.errors.EmptyDataError:
            logger.warning("Empty data file (no columns to parse): %s", csv_file)
            return None
        except (ValueError, KeyError) as e:
            logger.debug("Skipping file %s due to format issue: %s", csv_file, e)
            return None
        except Exception as e:
            logger.warning("Error parsing file %s: %s", csv_file, e)
            if self._params.strict_mode:
                raise
            return None

    def read_incremental(self) -> List[StepMetrics]:
        """
        Incrementally read new data from CSV files since last call.

        Tracks byte offsets per file and only reads newly appended data.
        For HCCL format, partial Id groups are buffered across scans.

        Returns:
            List of new StepMetrics parsed from newly appended CSV data.
        """
        directory = self._params.directory_path

        if not os.path.isdir(directory):
            logger.warning("Data directory not found: %s", directory)
            return []

        csv_files = sorted(
            f for f in os.listdir(directory) if f.endswith(".csv")
        )
        if not csv_files:
            return []

        all_new_metrics: List[StepMetrics] = []

        for csv_file in csv_files:
            if not is_standard_csv_filename(csv_file):
                continue

            filepath = os.path.join(directory, csv_file)
            try:
                current_size = os.path.getsize(filepath)
            except OSError:
                continue

            prev_offset = self._file_offsets.get(csv_file, 0)

            if current_size <= prev_offset:
                if current_size < prev_offset:
                    logger.info(
                        "File %s shrank (%d -> %d), resetting offset",
                        csv_file,
                        prev_offset,
                        current_size,
                    )
                    self._file_offsets[csv_file] = 0
                    self._file_headers.pop(csv_file, None)
                    self._hccl_partial_ids.pop(csv_file, None)
                continue

            file_format = self._resolve_format(csv_file, filepath)
            if file_format == DataFormat.UNKNOWN:
                continue

            new_metrics = self._read_incremental_file(
                csv_file, filepath, prev_offset, file_format
            )
            all_new_metrics.extend(new_metrics)
            self._file_offsets[csv_file] = current_size

        return all_new_metrics

    def _detect_format_from_directory(self, directory: str) -> DataFormat:
        csv_files = [f for f in os.listdir(directory) if f.endswith(".csv")]
        if not csv_files:
            return DataFormat.UNKNOWN

        for csv_file in csv_files:
            file_format = detect_format_by_filename(csv_file)
            if file_format != DataFormat.UNKNOWN:
                return file_format

        first_file = os.path.join(directory, csv_files[0])
        return detect_format_by_file(first_file)

    def _get_parser_for_format(self, data_format: DataFormat):
        if data_format == DataFormat.NCCL:
            return NCCLDataParser.parse
        elif data_format == DataFormat.HCCL:
            return HCCLDataParser.parse
        else:
            raise ValueError(f"Unknown data format: {data_format}")

    def _resolve_format(self, csv_file: str, filepath: str) -> DataFormat:
        if csv_file in self._file_formats:
            return self._file_formats[csv_file]

        fmt = detect_format_by_filename(csv_file)
        if fmt == DataFormat.UNKNOWN:
            fmt = detect_format_by_file(filepath)

        if fmt != DataFormat.UNKNOWN:
            self._file_formats[csv_file] = fmt

        return fmt

    def _read_incremental_file(
        self,
        csv_file: str,
        filepath: str,
        prev_offset: int,
        data_format: DataFormat,
    ) -> List[StepMetrics]:
        rank_id = extract_rank_from_filename(csv_file)
        ip_addr = extract_ip_from_filename(csv_file)

        if prev_offset == 0:
            return self._read_full_file(
                csv_file, filepath, rank_id, ip_addr, data_format
            )

        return self._read_appended_data(
            csv_file, filepath, prev_offset, rank_id, ip_addr, data_format
        )

    def _read_full_file(
        self,
        csv_file: str,
        filepath: str,
        rank_id: int,
        ip_addr: str,
        data_format: DataFormat,
    ) -> List[StepMetrics]:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                header_line = f.readline()
                self._file_headers[csv_file] = header_line
            df = pd.read_csv(filepath)
            if df.empty:
                return []
        except Exception as e:
            logger.warning("Failed to read file %s: %s", filepath, e)
            return []

        if data_format == DataFormat.HCCL:
            return self._parse_hccl_incremental(
                csv_file, df, rank_id, ip_addr
            )

        return self._parse_and_build(df, rank_id, ip_addr, data_format)

    def _read_appended_data(
        self,
        csv_file: str,
        filepath: str,
        prev_offset: int,
        rank_id: int,
        ip_addr: str,
        data_format: DataFormat,
    ) -> List[StepMetrics]:
        from io import StringIO

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                f.seek(prev_offset)
                new_content = f.read()
        except Exception as e:
            logger.warning("Failed to read appended data from %s: %s", filepath, e)
            return []

        if not new_content.strip():
            return []

        header_line = self._file_headers.get(csv_file, "")
        if not header_line:
            return []

        try:
            content = header_line + new_content
            df = pd.read_csv(StringIO(content))
            if df.empty:
                return []
        except Exception as e:
            logger.warning("Failed to parse appended data from %s: %s", filepath, e)
            return []

        if data_format == DataFormat.HCCL:
            return self._parse_hccl_incremental(
                csv_file, df, rank_id, ip_addr
            )

        return self._parse_and_build(df, rank_id, ip_addr, data_format)

    def _parse_hccl_incremental(
        self,
        csv_file: str,
        df: pd.DataFrame,
        rank_id: int,
        ip_addr: str,
    ) -> List[StepMetrics]:
        required_columns = ["Flag", "Id", "Kind", "Name", "SourceKind", "Timestamp"]
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            logger.warning(
                "HCCL data missing required columns: %s", missing_columns
            )
            return []

        partial_ids = self._hccl_partial_ids.get(csv_file, {})

        grouped = df.groupby("Id")
        complete_records = []
        still_partial_ids = set()

        for id_val, group in grouped:
            record = self._merge_hccl_id_group(partial_ids, id_val, group)
            if record is not None:
                complete_records.append(record)
            else:
                still_partial_ids.add(id_val)
                partial_ids[id_val] = self._extract_partial_hccl(group)

        self._hccl_partial_ids[csv_file] = {
            k: v for k, v in partial_ids.items() if k in still_partial_ids
        }

        if not complete_records:
            return []

        parsed_df = pd.DataFrame(complete_records)
        return self._build_metrics_from_parsed(
            parsed_df, rank_id, ip_addr, DataFormat.HCCL
        )

    def _merge_hccl_id_group(
        self,
        partial_ids: Dict[int, dict],
        id_val: int,
        group: pd.DataFrame,
    ) -> Optional[dict]:
        t1 = None
        t2 = None
        t3 = None
        t4 = None
        op_name = None

        if id_val in partial_ids:
            prev = partial_ids[id_val]
            t1 = prev.get("t1")
            t2 = prev.get("t2")
            t3 = prev.get("t3")
            t4 = prev.get("t4")
            op_name = prev.get("op_name")

        for _, row in group.iterrows():
            flag = row["Flag"]
            source_kind = row["SourceKind"]
            timestamp = row["Timestamp"]
            name = row["Name"]

            if source_kind == HCCLDataParser.SOURCE_HOST:
                if flag == HCCLDataParser.FLAG_START:
                    t1 = timestamp
                elif flag == HCCLDataParser.FLAG_END:
                    t2 = timestamp
                if pd.notna(name) and name and op_name is None:
                    op_name = HCCLDataParser._extract_op_name(name)
            elif source_kind == HCCLDataParser.SOURCE_DEVICE:
                if flag == HCCLDataParser.FLAG_START:
                    t3 = timestamp
                elif flag == HCCLDataParser.FLAG_END:
                    t4 = timestamp

        if t1 is None or t3 is None:
            return None

        if op_name is None:
            op_name = f"unknown_op_id_{id_val}"

        return {
            "op_name": op_name,
            "t1": t1,
            "t2": t2 if t2 is not None else np.nan,
            "t3": t3,
            "t4": t4 if t4 is not None else np.nan,
        }

    def _extract_partial_hccl(self, group: pd.DataFrame) -> dict:
        partial: dict = {}
        for _, row in group.iterrows():
            flag = row["Flag"]
            source_kind = row["SourceKind"]
            timestamp = row["Timestamp"]
            name = row["Name"]

            if source_kind == HCCLDataParser.SOURCE_HOST:
                if flag == HCCLDataParser.FLAG_START:
                    partial["t1"] = timestamp
                elif flag == HCCLDataParser.FLAG_END:
                    partial["t2"] = timestamp
                if pd.notna(name) and name and "op_name" not in partial:
                    partial["op_name"] = HCCLDataParser._extract_op_name(name)
            elif source_kind == HCCLDataParser.SOURCE_DEVICE:
                if flag == HCCLDataParser.FLAG_START:
                    partial["t3"] = timestamp
                elif flag == HCCLDataParser.FLAG_END:
                    partial["t4"] = timestamp

        return partial

    def _parse_and_build(
        self,
        df: pd.DataFrame,
        rank_id: int,
        ip_addr: str,
        data_format: DataFormat,
    ) -> List[StepMetrics]:
        if data_format == DataFormat.HCCL:
            parsed_df = HCCLDataParser.parse(df, rank_id)
        elif data_format == DataFormat.NCCL:
            parsed_df = NCCLDataParser.parse(df, rank_id)
        else:
            return []

        if parsed_df.empty:
            return []

        return self._build_metrics_from_parsed(
            parsed_df, rank_id, ip_addr, data_format
        )

    def _build_metrics_from_parsed(
        self,
        parsed_df: pd.DataFrame,
        rank_id: int,
        ip_addr: str,
        data_format: DataFormat,
    ) -> List[StepMetrics]:
        metrics = []
        for _, row in parsed_df.iterrows():
            record = {
                "op_name": row["op_name"],
                "t1": row["t1"],
                "t2": row["t2"],
                "t3": row["t3"],
                "t4": row["t4"],
                "step": int(row["step"])
                if "step" in parsed_df.columns and pd.notna(row.get("step"))
                else 0,
                "ip": ip_addr,
                "data_format": data_format,
            }
            sm = build_step_metrics(rank_id, record, data_format)
            if sm is not None:
                metrics.append(sm)
        return metrics

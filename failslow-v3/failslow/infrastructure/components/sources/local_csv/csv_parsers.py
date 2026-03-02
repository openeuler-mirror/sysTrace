"""
Shared CSV parsing utilities for NCCL and HCCL format data.

Provides public API for format detection, data parsing, and StepMetrics
construction. Used by both LocalCsvDataSource (batch mode) and
incremental reading scenarios.
"""

import logging
import os
import re
from enum import Enum
from typing import Dict, Optional

import numpy as np
import pandas as pd

from failslow.domain.models import KernelType, StepMetrics

logger = logging.getLogger(__name__)


class DataFormat(Enum):
    HCCL = "hccl"
    NCCL = "nccl"
    UNKNOWN = "unknown"


class NCCLDataParser:
    """Parser for NCCL format data."""

    DEFAULT_TIME_UNIT = "us"

    @staticmethod
    def parse(df: pd.DataFrame, rank: int) -> pd.DataFrame:
        required_columns = ["kernel", "t1", "t2", "t3", "t4"]
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            raise ValueError(
                f"NCCL data missing required columns: {missing_columns}. "
                f"Available columns: {df.columns.tolist()}"
            )

        result = df[required_columns].copy()
        result = result.rename(columns={"kernel": "op_name"})

        if "step" in df.columns:
            result["step"] = df["step"]

        logger.debug("Parsed NCCL data: %d rows, rank=%d", len(result), rank)
        return result


class HCCLDataParser:
    """Parser for HCCL format data."""

    DEFAULT_TIME_UNIT = "ns"

    FLAG_START = 16
    FLAG_END = 32
    SOURCE_HOST = 0
    SOURCE_DEVICE = 1

    @staticmethod
    def parse(df: pd.DataFrame, rank: int) -> pd.DataFrame:
        required_columns = ["Flag", "Id", "Kind", "Name", "SourceKind", "Timestamp"]
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            raise ValueError(
                f"HCCL data missing required columns: {missing_columns}. "
                f"Available columns: {df.columns.tolist()}"
            )

        records = []
        grouped = df.groupby("Id")
        total_ids = len(grouped)
        incomplete_ids = 0

        for id_val, group in grouped:
            record = HCCLDataParser._parse_id_group(group, id_val)
            if record is not None:
                records.append(record)
            else:
                incomplete_ids += 1

        if incomplete_ids > 0:
            logger.warning(
                "HCCL data has %d incomplete Id groups, skipped. Total: %d, Parsed: %d",
                incomplete_ids,
                total_ids,
                len(records),
            )

        if not records:
            logger.warning("No valid records parsed from HCCL data for rank %d", rank)
            return pd.DataFrame(columns=["op_name", "t1", "t2", "t3", "t4"])

        result = pd.DataFrame(records)
        logger.debug("Parsed HCCL data: %d rows, rank=%d", len(result), rank)
        return result

    @staticmethod
    def _parse_id_group(group: pd.DataFrame, id_val: int) -> Optional[dict]:
        t1 = None
        t2 = None
        t3 = None
        t4 = None
        op_name = None

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
            logger.debug(
                "Id %d incomplete: missing host start (t1=%s) or device start (t3=%s)",
                id_val,
                t1,
                t3,
            )
            return None

        if op_name is None:
            op_name = f"unknown_op_id_{id_val}"
            logger.debug("Id %d has no op_name, using default: %s", id_val, op_name)

        return {
            "op_name": op_name,
            "t1": t1,
            "t2": t2 if t2 is not None else np.nan,
            "t3": t3,
            "t4": t4 if t4 is not None else np.nan,
        }

    @staticmethod
    def _extract_op_name(raw_name: str) -> str:
        if raw_name.startswith("comm:"):
            name_part = raw_name[5:]
            if "!" in name_part:
                return name_part.split("!")[0]
            return name_part
        if "!" in raw_name:
            return raw_name.split("!")[0]
        return raw_name


def is_standard_csv_filename(filename: str) -> bool:
    basename = os.path.splitext(filename)[0]
    if not re.search(r"[.-]\d+$", basename):
        return False
    for suffix in ("_with_delta", "_device", "_op_launch"):
        if basename.endswith(suffix):
            return False
    return True


def extract_rank_from_filename(filename: str) -> int:
    basename = os.path.splitext(filename)[0]
    match = re.search(r"-(\d+)$", basename)
    if match:
        return int(match.group(1))
    match = re.search(r"\.(\d+)$", basename)
    if match:
        return int(match.group(1))
    logger.warning("Could not extract rank from filename: %s", filename)
    return 0


def extract_ip_from_filename(filename: str) -> str:
    match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", filename)
    if match:
        return match.group(1)
    return "0.0.0.0"


def detect_format_by_filename(filename: str) -> DataFormat:
    filename_lower = filename.lower()
    if filename_lower.startswith("hccl_activity-"):
        return DataFormat.NCCL
    elif filename_lower.startswith("mspti-marker-"):
        return DataFormat.HCCL
    return DataFormat.UNKNOWN


def detect_format_by_columns(df: pd.DataFrame) -> DataFormat:
    columns_set = set(df.columns)
    nccl_required = {"kernel", "t1", "t2", "t3", "t4"}
    hccl_required = {"Flag", "Id", "Kind", "Name", "SourceKind", "Timestamp"}
    if nccl_required.issubset(columns_set):
        return DataFormat.NCCL
    elif hccl_required.issubset(columns_set):
        return DataFormat.HCCL
    return DataFormat.UNKNOWN


def detect_format_by_file(filepath: str) -> DataFormat:
    try:
        df = pd.read_csv(filepath, nrows=1)
        return detect_format_by_columns(df)
    except Exception as e:
        logger.warning("Failed to read file for format detection: %s", e)
    return DataFormat.UNKNOWN


def build_step_metrics(
    rank_id: int, record: Dict, data_format: DataFormat
) -> Optional[StepMetrics]:
    if pd.isna(record["t1"]) or record["t1"] == 0:
        logger.debug("Skipping record with missing t1: rank=%d, op=%s", rank_id, record.get("op_name"))
        return None
    if pd.isna(record["t3"]) or record["t3"] == 0:
        logger.debug("Skipping record with missing t3: rank=%d, op=%s", rank_id, record.get("op_name"))
        return None
    if pd.isna(record["t4"]):
        logger.debug("Skipping record with missing t4: rank=%d, op=%s", rank_id, record.get("op_name"))
        return None

    time_unit_conversion = 1000.0 if data_format == DataFormat.NCCL else 1.0

    t1_ns = int(record["t1"] * time_unit_conversion)
    t2_ns = int(record["t2"] * time_unit_conversion) if pd.notna(record["t2"]) and record["t2"] != 0 else 0
    t3_ns = int(record["t3"] * time_unit_conversion)
    t4_ns = int(record["t4"] * time_unit_conversion)
    t_delta_ns = t3_ns - t2_ns
    t_exec_ns = t4_ns - t3_ns

    kernel = KernelType(
        name=record["op_name"],
        t1_ns=t1_ns,
        t2_ns=t2_ns,
        t_delta_ns=t_delta_ns,
        t_exec_ns=t_exec_ns,
        t3_ns=t3_ns,
        t4_ns=t4_ns,
    )

    step = record.get("step", 0) if record.get("step", 0) > 0 else 0
    node_ip = record.get("ip", "0.0.0.0")

    return StepMetrics(
        start_time_ns=t1_ns,
        end_time_ns=t4_ns,
        step=step,
        rank_id=rank_id,
        local_rank_id=0,
        node_ip=node_ip,
        node_port=0,
        kernels=[kernel],
    )

import pandas as pd
import numpy as np
from .data import Data
from ..logging_utils import get_logger
import logging
from typing import Tuple
from .time_transformer import TimeColumnTransformer

logger = get_logger(__name__)



class TimeSeriesData(Data):
    def __init__(self, df: pd.DataFrame, time_col: str | None = None):
        self.df = df.copy()
        if not self.verify_data():
            err_msg = "Provided data does not meet the required specifications."
            logger.error(err_msg)
            raise ValueError(err_msg)
        # reorganize columns: first column is time, others are values
        self.time_column = self.detect_time_column(df) if time_col is None else time_col
        self.value_columns = [col for col in df.columns if col != self.time_column]
        self.df = self.df[[self.time_column] + self.value_columns]
        self._transform_time_column()

    def _transform_time_column(self):
        """
        转为ms时间戳(float类型)
        1. 检测原始时间列的数据格式 (字符串、datetime、ms、s、us等)
        2. 转为ms时间戳(float类型)
        3. 替换原始时间列
        """

        # Delegate parsing to a dedicated transformer class for clarity and testability
        s = self.df[self.time_column]
        n = len(s)

        # preserve original column if not already present
        orig_col = f"_orig_{self.time_column}"
        if orig_col not in self.df.columns:
            try:
                self.df[orig_col] = s.copy()
            except Exception:
                logger.debug(
                    "Could not preserve original time column under %s", orig_col
                )

        # Use TimeColumnTransformer to produce ms series
        transformer = TimeColumnTransformer(s, logger=logger)
        ms = transformer.transform()

        # 3) Logging for failures
        failed = int(ms.isna().sum())
        if failed > 0:
            logger.warning(
                "Time column '%s': %d/%d values could not be parsed and are set to NaN",
                self.time_column,
                failed,
                n,
            )

        # 4) Replace original time column with float ms values
        try:
            self.df[self.time_column] = ms.astype("float64")
        except Exception:
            self.df[self.time_column] = ms

        # 5) Inform about monotonicity (debug only)
        try:
            non_na_series = self.df[self.time_column].dropna()
            if len(non_na_series) > 1 and not non_na_series.is_monotonic_increasing:
                logger.debug(
                    "Time column '%s' is not monotonically increasing.",
                    self.time_column,
                )
        except Exception:
            pass

    def detect_time_column(self, df: pd.DataFrame) -> str:
        """自动检测时间所在的列"""
        # 根据关键字检测
        keywords = ["time", "timestamp", "date", "datetime"]
        for col in df.columns:
            if any(keyword in col.lower() for keyword in keywords):
                logger.verbose(f"Detected time column by keyword : %s", col)
                return col
        # 根据数据类型检测
        for col in df.columns:
            if pd.api.types.is_datetime64_any_dtype(df[col]):
                logger.verbose(f"Detected time column by datetime dtype: %s", col)
                return col
        # 根据间隔的均匀程度检测，间隔均匀的大概率是时间列
        for col in df.columns:
            if not pd.api.types.is_numeric_dtype(df[col]):
                continue  # 非数值列，直接跳过
            try:
                diffs = df[col].sort_values().diff().dropna()
                n_unique_diffs = diffs.nunique()
                if n_unique_diffs <= 10:
                    if logger.isEnabledFor(logging.DEBUG):
                        most_common_diff = diffs.mode()[0]
                        logger.verbose(
                            f"Detected time column by interval uniformity: {col} "
                            f"(most common diff: {most_common_diff}, unique diffs: {n_unique_diffs})"
                        )
                    return col
            except (TypeError, ValueError):
                # 可能是列类型不支持排序或差分（如 object 含非数值）
                continue
        # 仍然没有检测到，返回第一列
        logger.warning("Could not detect time column, defaulting to the first column.")
        return df.columns[0]

    def verify_data(self) -> bool:
        """检查数据是否符合对应需求"""
        if self.df.empty:
            logger.error("DataFrame is empty.")
            return False
        if len(self.df.columns) < 1:
            logger.error("DataFrame must have at least one column for time.")
            return False
        return True

    def get_data(self) -> pd.DataFrame:
        return self.df

    def get_time_column(self) -> pd.Series:
        return self.df[self.time_column]

    def append(self, other: "TimeSeriesData") -> None:
        """在当前数据后追加另一段时间序列数据"""
        if not isinstance(other, TimeSeriesData):
            raise ValueError("Can only append another TimeSeriesData instance.")
        other_data = other.get_data().copy()
        # index alignment check
        if set(self.df.columns) != set(other_data.columns):
            err_msg = "Column mismatch: cannot append data with different columns."
            logger.error(err_msg)
            raise ValueError(err_msg)
        # time alignment: only append data with time greater than current max time
        other_data = other_data[other_data[self.time_column] > self.df[self.time_column].max()]
        if other_data.empty:
            logger.debug("No new data to append based on time alignment.")
            return
        self.df = pd.concat([self.df, other_data], ignore_index=True).reset_index(drop=True)
        self._transform_time_column()  # 重新转换时间列，确保正确性

__all__ = ["TimeSeriesData"]

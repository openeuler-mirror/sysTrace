import logging
import pandas as pd
import numpy as np
import warnings
import logging


class TimeColumnTransformer:
    """
    Helper class to transform a pandas Series representing time into float milliseconds.

    It exposes `transform()` which orchestrates several `_check_xxx` methods. Each
    `_check_xxx` attempts to parse/convert the input series and returns a `pd.Series`
    of ms values for the entries it could handle, or `None` if it didn't handle any.

    The orchestration fills values in order: ISO/datetime parsing, explicit formats,
    then numeric inference. Unparsed entries remain NaN.
    """

    def __init__(self, series: pd.Series, logger: logging.Logger = None):
        self.series = series
        self.index = series.index
        self.logger = logger or logging.getLogger(__name__)

    def transform(self) -> pd.Series:
        """Orchestrate parsing steps and return float-ms pd.Series.

        Returns:
            pd.Series: float ms values (NaN where parsing failed)
        """
        n = len(self.series)
        ms = pd.Series(np.nan, index=self.index, dtype="float64")

        # 1) ISO / generic datetime parsing
        dt_ms = self._check_iso_datetime(self.series)
        if dt_ms is not None:
            # 将通过 pd.to_datetime 成功解析的条目写入 ms 结果
            mask_dt = dt_ms.notna()
            if mask_dt.any():
                ms.loc[mask_dt] = dt_ms.loc[mask_dt]
        # 2) Explicit formats for remaining strings
        # 注意：这里的 fmt_ms 仅包含显式格式解析成功的条目；
        # parsed_context（传给 _check_numeric）会把 dt_ms 与 fmt_ms 合并，
        # 以便后续的数值推断可以使用所有已知的绝对时间信息。
        remaining_mask = ms.isna()
        fmt_ms = None
        if remaining_mask.any():
            fmt_ms = self._check_explicit_formats(self.series[remaining_mask])
            if fmt_ms is not None:
                ms.loc[fmt_ms.index] = fmt_ms

        # 3) Numeric inference for anything left
        # Pass parsed context (dt_ms and fmt_ms) to _check_numeric so it can perform
        # context-based inference instead of recomputing parsed values internally.
        remaining_mask = ms.isna()
        if remaining_mask.any():
            # build parsed context: combine dt_ms and fmt_ms (may be None)
            parsed_context = None
            if dt_ms is not None:
                parsed_context = dt_ms.copy()
            if fmt_ms is not None:
                if parsed_context is None:
                    parsed_context = fmt_ms.copy()
                else:
                    parsed_context = parsed_context.combine_first(fmt_ms)
            if parsed_context is not None:
                num_ms = self._check_numeric_by_known_anchors(
                    self.series[remaining_mask], parsed_context=parsed_context
                )
                if num_ms is not None:
                    ms.loc[num_ms.index] = num_ms
        # 4) Fallback numeric inference by datetime validity
        remaining_mask = ms.isna()
        if remaining_mask.any():
            num_ms = self._check_numeric_by_datetime_validity(
                self.series[remaining_mask]
            )
            if num_ms is not None:
                ms.loc[num_ms.index] = num_ms
        # 5) Final
        # logging about failures
        failed = int(ms.isna().sum())
        if failed > 0:
            self.logger.warning(
                "Time column processing: %d/%d values could not be parsed and are set to NaN",
                failed,
                n,
            )

        return ms

    def _check_iso_datetime(self, s: pd.Series) -> pd.Series | None:
        """Attempt to parse values using `pd.to_datetime` (vectorized).

        Handles: pandas datetime64 series, pandas.Timestamp, ISO-8601 strings.

        Example:
            Series(['1970-01-01T00:00:00Z', '1970-01-01T00:00:01Z']) -> Series([0.0, 1000.0])
        """
        if pd.api.types.is_numeric_dtype(s):
            return None
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)    
                s_dt = pd.to_datetime(s, utc=True, errors="coerce")
        except Exception:
            return None
        if not s_dt.notna().any():
            return None
        # Build output and ensure NaT positions remain NaN (avoid int64-min artifacts)
        out = pd.Series(np.nan, index=self.index, dtype="float64")
        mask = s_dt.notna()
        if mask.any():
            try:
                ns = s_dt[mask].astype("int64")
                out.loc[mask] = ns / 1e6
            except Exception:
                for idx in s_dt[mask].index:
                    try:
                        out.loc[idx] = s_dt.loc[idx].value / 1e6
                    except Exception:
                        out.loc[idx] = np.nan
        return out

    def _check_explicit_formats(self, s: pd.Series) -> pd.Series | None:
        """Try parsing with explicit datetime formats.

        Handles strings like 'YYYY-mm-dd HH:MM:SS[.ffffff]'.

        Example:
            Series(['1970-01-01 00:00:00', '1970-01-01 00:00:00.500']) -> Series([0.0, 500.0])
        """
        if s.empty:
            return None
        formats = ["%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"]
        out = pd.Series(np.nan, index=s.index, dtype="float64")
        any_parsed = False
        for fmt in formats:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    parsed = pd.to_datetime(s, format=fmt, utc=True, errors="coerce")
            except Exception:
                continue
            ok = parsed.notna()
            if ok.any():
                any_parsed = True
                try:
                    ns = parsed[ok].astype("int64")
                    out.loc[ns.index] = ns / 1e6
                except Exception:
                    for idx in parsed[ok].index:
                        try:
                            out.loc[idx] = parsed.loc[idx].value / 1e6
                        except Exception:
                            out.loc[idx] = np.nan
        return out if any_parsed else None

    def _check_numeric_by_datetime_validity(
        self, s: pd.Series, year_range=[-100, 100]
    ) -> pd.Series | None:
        """
        根据数据的位数进行推测，时间戳需要一般落在当前年份前后100年之间
        """
        current_year = pd.Timestamp.now(tz="UTC").year
        min_year = current_year + year_range[0]
        max_year = current_year + year_range[1]

        out = pd.Series(np.nan, index=s.index, dtype="float64")
        any_parsed = False

        for unit, factor in [("s", 1e3), ("ms", 1), ("us", 1e-3), ("ns", 1e-6)]:
            try:
                dt_parsed = pd.to_datetime(
                    s.astype("float64"), unit=unit, utc=True, errors="coerce"
                )
            except Exception:
                dt_parsed = pd.Series([pd.NaT] * len(s), index=s.index)
            ok = dt_parsed.notna()
            if ok.any():
                years = dt_parsed[ok].dt.year
                valid_years = (years >= min_year) & (years <= max_year)
                if valid_years.any():
                    any_parsed = True
                    try:
                        ns = dt_parsed[ok][valid_years].astype("int64")
                        out.loc[ns.index] = ns / 1e6
                    except Exception:
                        for idx in dt_parsed[ok][valid_years].index:
                            try:
                                out.loc[idx] = dt_parsed.loc[idx].value / 1e6
                            except Exception:
                                out.loc[idx] = np.nan

        return out if any_parsed else None

    def _check_numeric_by_known_anchors(
        self, s: pd.Series, parsed_context: pd.Series | None = None
    ):
        """
        根据已知的时间锚点进行推测
        Example:
            Series(["1970-01-01T00:00:00Z", "1970-01-01 00:00:01.000", 601990000, 603010000]) ->
            Series([0.0, 1000.0, 1990.0, 3010.0])
        """
        # 1. 计算已知点的intervel中间值
        parsed_context = parsed_context.dropna()
        if len(parsed_context) < 2:
            return None  # 不足以计算间隔中间值

        expected_intervals = (
            parsed_context.diff() / parsed_context.index.to_series().diff()
        )
        expected_interval_median = expected_intervals.dropna().median()

        # 2. 计算(筛掉上面context里的)有数点的interval中间值
        left_s = s.dropna()
        left_s = left_s[~left_s.index.isin(parsed_context.index)]
        if len(left_s) < 2:
            return None  # 剩余数值点过少

        left_intervals = left_s.diff() / left_s.index.to_series().diff()
        left_interval_median = left_intervals.dropna().median()

        # 3. 根据interval_median计算比例因子，按照预期，这两个值的log10应该是接近的
        if left_interval_median <= 0 or expected_interval_median <= 0:
            self.logger.debug("Non-positive interval median encountered.")
            return None  # 非正数，无法计算比例因子

        log10_ratio = np.log10(expected_interval_median) - np.log10(
            left_interval_median
        )
        scale_factor = 10 ** round(log10_ratio)

        # 计算预期的时间间隔，这个时间间隔理应是一个整数倍数 例如：1120 → 1100, 999 → 1000
        expected_interval = left_interval_median * scale_factor
        digit = int(np.round(np.log10(expected_interval)))
        digit = 10**digit
        digit /= 10
        expected_interval = round(expected_interval / digit) * digit
        self.logger.verbose(
            f"Numeric time parsing: interval %s ms.",
            expected_interval,
        )

        # 4. 应用比例因子进行转换，此后例子中的601990000, 603010000 应该转为 601990.0, 603010.0
        out = left_s.astype("float64") * scale_factor

        # 5. 计算水平偏移使得数据能够接上已知点
        # 此时，out中的数据，应该 表达为 value = index * expected_interval + offset_1
        # 而已知点 parsed_context 中的数据，表达为 value = index * expected_interval + offset_2
        # 需要计算 offset_1 和 offset_2 之间的差值 delta_offset
        offset_1 = np.median(out - left_s.index.to_series() * expected_interval)
        offset_2 = np.median(
            parsed_context - parsed_context.index.to_series() * expected_interval
        )
        delta_offset = offset_2 - offset_1
        out += delta_offset
        return out

import numpy as np
import pandas as pd
from scipy.ndimage import gaussian_filter1d


def agg_data_by_time(
    time_series: pd.Series,
    values: pd.Series,
    align_interval,
    target_interval,
    smooth_func,
    smooth_window,
    agg_func,
    agg_args=None,
    agg_kwargs=None,
) -> pd.Series:
    time_col = "time"
    val_col = "value"
    if agg_args is None:
        agg_args = []
    if agg_kwargs is None:
        agg_kwargs = {}

    rank_data = pd.DataFrame({time_col: time_series, val_col: values})
    rank_data[time_col] = (
        rank_data[time_col] - rank_data[time_col].min()
    ) // target_interval

    rank_data[time_col] = (
        (rank_data[time_col] - rank_data[time_col].min())
        // align_interval
        * align_interval
    )
    # 忽略第一个点
    rank_data = rank_data[rank_data[time_col] > 0]
    # 忽略极大值
    rank_data = rank_data[rank_data[val_col] < rank_data[val_col].quantile(0.999)]
    # 忽略极小值
    rank_data = rank_data[rank_data[val_col] > rank_data[val_col].quantile(0.001)]
    data_grouped = rank_data.groupby([time_col]).agg(
        {val_col: lambda x: agg_func(x, *agg_args, **agg_kwargs)}
    )

    if data_grouped.empty:
        return None

    # 平滑数据
    data_grouped["smooth"] = smooth(data_grouped[val_col], smooth_func, smooth_window)
    return data_grouped["smooth"]


def smooth(data_col, smooth_func, smooth_window):
    # 平滑数据
    if smooth_func == "mean":
        return data_col.rolling(window=smooth_window, min_periods=1, center=True).mean()
    elif smooth_func == "median":
        return data_col.rolling(
            window=smooth_window, min_periods=1, center=True
        ).median()
    elif smooth_func == "gaussian":
        # 经验规则：窗口 ≈ 6σ 覆盖 99% 的高斯分布
        return gaussian_filter1d(
            data_col,
            sigma=smooth_window / 6,
            mode="nearest",
        )
    return data_col

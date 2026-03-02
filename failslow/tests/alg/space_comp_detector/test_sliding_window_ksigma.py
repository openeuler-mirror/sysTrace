import os
import pytest
import numpy as np
import pandas as pd
from failslow.alg.space_comp_detector.sliding_window_ksigma import SlidingWindowKSigma


def test_sliding_window_ksigma_demo_csvs():
	target_csvs = [
		"../local/analysis_0123.csv",
		"../local/analysis_4567.csv",
		"../local/analysis_0123.1.csv",
		"../local/analysis_4567.1.csv",
		"../local/analysis_01234567.dp8.csv",
	]

	detector_cfg = {}
	detector = SlidingWindowKSigma(detector_cfg)

	for csv_file in target_csvs:
		if not os.path.exists(csv_file):
			pytest.skip(f"Missing demo CSV: {csv_file}")
		df = pd.read_csv(csv_file)
		data = df.values
		labels = detector.detect(data)

		assert labels.shape == data.shape
		assert np.isin(labels, [0, 1]).all()


def test_sliding_window_ksigma_from_split_csvs():
	csv_path = "tests/local/debug/fail_slow_detect_debug"
	csvs = os.listdir(csv_path)
	# example: rank_0_ncclDevKernel_AllReduce_Sum_f32_RING_LL_group0123_debug
	target_csvs = [e for e in csvs if e.startswith("rank_") and e.endswith("debug.csv")]
	df = pd.DataFrame({"csv": target_csvs})
	df["group_indexs"] = df["csv"].apply(lambda x: x.split("group")[1].split("_")[0])



if __name__ == "__main__":
	test_sliding_window_ksigma_demo_csvs()
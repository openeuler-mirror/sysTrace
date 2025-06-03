# coding=utf-8
"""
Copyright (c) Huawei Technologies Co., Ltd. 2020-2028. All rights reserved.
Description:
FileName：fft.py
Author: h00568282/huangbin 
Create Date: 2025/3/7 19:28
Notes:

"""
import numpy as np
import matplotlib.pyplot as plt

def calculate_period(data):
    # 进行傅里叶变换
    fft_values = np.fft.fft(data)
    frequencies = np.fft.fftfreq(len(data), t[1] - t[0])

    # 取绝对值并找到主要频率
    abs_fft = np.abs(fft_values)
    positive_frequencies = frequencies[:len(frequencies) // 2]
    positive_abs_fft = abs_fft[:len(abs_fft) // 2]
    main_frequency_index = np.argmax(positive_abs_fft)
    main_frequency = positive_frequencies[main_frequency_index]

    # 估计周期
    estimated_period = 1 / main_frequency if main_frequency != 0 else None
    print(f"Estimated period: {estimated_period}")

    # 绘制频域图
    plt.figure(figsize=(10, 6))
    plt.plot(positive_frequencies, positive_abs_fft)
    plt.xlabel('Frequency')
    plt.ylabel('Amplitude')
    plt.title('Frequency Spectrum')
    plt.show()
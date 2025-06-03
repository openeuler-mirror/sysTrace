# coding=utf-8
"""
Copyright (c) Huawei Technologies Co., Ltd. 2020-2028. All rights reserved.
Description:
FileName：kmeans_cluster.py
Author: h00568282/huangbin 
Create Date: 2025/3/7 14:15
Notes:

"""


import numpy as np
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans

# 生成示例时序数据
np.random.seed(42)
n_samples = 100
n_time_steps = 20

# 生成三种不同分布的时序数据
data_cluster_1 = np.random.normal(loc=0, scale=1, size=(n_samples // 3, n_time_steps))
data_cluster_2 = np.random.normal(loc=5, scale=2, size=(n_samples // 3, n_time_steps))
data_cluster_3 = np.random.normal(loc=-5, scale=1.5, size=(n_samples - 2 * (n_samples // 3), n_time_steps))

# 合并数据
data = np.vstack((data_cluster_1, data_cluster_2, data_cluster_3))

# 提取特征（均值和标准差）
features = np.hstack((np.mean(data, axis=1).reshape(-1, 1), np.std(data, axis=1).reshape(-1, 1)))

# 使用 K - 均值聚类进行分类
n_clusters = 3
kmeans = KMeans(n_clusters=n_clusters, random_state=42)
labels = kmeans.fit_predict(features)

# 可视化分类结果
plt.figure(figsize=(12, 6))
colors = ['r', 'g', 'b']
for i in range(n_clusters):
    cluster_data = data[labels == i]
    for j in range(cluster_data.shape[0]):
        plt.plot(cluster_data[j], color=colors[i], alpha=0.5)

plt.title('Classification of Time Series Data')
plt.xlabel('Time Step')
plt.ylabel('Value')
plt.show()
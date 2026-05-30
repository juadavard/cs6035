import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from yellowbrick.cluster import KElbowVisualizer
class KmeansClustering:
    def __init__(self,random_state: int, init: str, n_init: int, max_iter: int, algorithm: str,tol: float):
        # TODO: Read the function description in https://github.gatech.edu/pages/cs6035-tools/cs6035-tools.github.io/Projects/Machine_Learning/Task3.html and implement the function as described
        pass

    def kmeans_get_n_clusters(self, train_features:pd.DataFrame) -> int:
        # TODO: Read the function description in https://github.gatech.edu/pages/cs6035-tools/cs6035-tools.github.io/Projects/Machine_Learning/Task3.html and implement the function as described
        k = int
        return k

    def kmeans_train(self, train_features: pd.DataFrame, k:int=None) -> list:
        # TODO: Read the function description in https://github.gatech.edu/pages/cs6035-tools/cs6035-tools.github.io/Projects/Machine_Learning/Task3.html and implement the function as described
        cluster_ids = list()
        return cluster_ids

    def kmeans_test(self, test_features: pd.DataFrame) -> list:
        # TODO: Read the function description in https://github.gatech.edu/pages/cs6035-tools/cs6035-tools.github.io/Projects/Machine_Learning/Task3.html and implement the function as described
        cluster_ids = list()
        return cluster_ids


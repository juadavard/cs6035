import numpy as np
import pandas as pd

def find_data_type(dataset:pd.DataFrame,column_name:str) -> np.dtype:
    return dataset[column_name].dtypes

# https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.DataFrame.reindex.html
def set_index_col(dataset:pd.DataFrame,index:pd.Series) -> pd.DataFrame:
    return dataset.reindex(index)

# https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.DataFrame.reset_index.html#pandas.DataFrame.reset_index
def reset_index_col(dataset:pd.DataFrame) -> pd.DataFrame:
    return dataset.reset_index(drop=True)

https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.astype.html
def set_col_type(dataset:pd.DataFrame,column_name:str,new_col_type:type) -> pd.DataFrame:
    dataset[column_name] = dataset[column_name].astype(new_col_type)
    return dataset

def make_DF_from_2d_array(array_2d:np.array,column_name_list:list[str],index:pd.Series) -> pd.DataFrame:
    df = pd.DataFrame.from_records(array_2d, index=index, columns=column_name_list)
    return df

# https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.sort_values.html
def sort_DF_by_column(dataset:pd.DataFrame,column_name:str,descending:bool) -> pd.DataFrame:
    return dataset.sort_values(by=[column_name], ascending=not descending)

# https://pandas.pydata.org/pandas-docs/version/2.3/reference/api/pandas.DataFrame.dropna.html
def drop_NA_cols(dataset:pd.DataFrame) -> pd.DataFrame:
    return dataset.dropna(axis=1)

def drop_NA_rows(dataset:pd.DataFrame) -> pd.DataFrame:
    return dataset.dropna(axis=1)

def make_new_column(dataset:pd.DataFrame,new_column_name:str,new_column_value:list) -> pd.DataFrame:
    dataset[new_column_name] = new_column_values
    return dataset

#https://pandas.pydata.org/pandas-docs/version/2.3/reference/api/pandas.DataFrame.merge.html#pandas.DataFrame.merge
def left_merge_DFs_by_column(left_dataset:pd.DataFrame,right_dataset:pd.DataFrame,join_col_name:str) -> pd.DataFrame:
    return left_dataset.merge(right_dataset)

class simpleClass():
    # TODO: Read https://github.gatech.edu/pages/cs6035-tools/cs6035-tools.github.io/Projects/Machine_Learning/Task1.html and implement the function as described
    def __init__(self, length:int, width:int, height:int):
        self.length = length
        self.width = width
        self.height = height

def find_dataset_statistics(dataset:pd.DataFrame,label_col:str) -> tuple[int,int,int,int,int]:
    # TODO: Read https://github.gatech.edu/pages/cs6035-tools/cs6035-tools.github.io/Projects/Machine_Learning/Task1.html and implement the function as described

    
    n_records = dataset.size() # TODO
    n_columns = dataset.columns().size # TODO
    n_negative = dataset[label].gt(0) # TODO
    n_positive = int # TODO
    perc_positive =  int# TODO

    return n_records,n_columns,n_negative,n_positive,perc_positive

# -*- coding: utf-8 -*-
"""
Created on Wed Sep  1 08:16:36 2021

@author: Nitesh
"""

#from nsepython
from nsepython import *   
import pandas as pd
x=nse_holidays()
# print((x.keys()))
# print(x['FO'])
df=pd.DataFrame(x['FO'])
df.to_csv('holiday.csv')
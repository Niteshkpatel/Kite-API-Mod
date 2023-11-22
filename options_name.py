# -*- coding: utf-8 -*-
"""
Created on Wed Sep  1 09:32:27 2021

@author: Nitesh
"""

from datetime import datetime, timedelta
import pandas as pd


def getHolidays():
    # with open('holiday.csv',r):
    df = pd.read_csv('holiday.csv')
    df['tradingDate'] = pd.to_datetime(df['tradingDate'])
    return df['tradingDate'].dt.date
def isHoliday(datetimeObj):
    # dayOfWeek = calendar.day_name[datetimeObj.weekday()]
    if datetimeObj.isoweekday()  == 6 or datetimeObj.isoweekday() == 7 :
      return True

    holidays = getHolidays()
    # print('Holiday check : ',(datetimeObj.date()))
    # for day in holidays:
        # print (day.date)
    # print((holidays.values))
    if (datetimeObj.date() in holidays.values):
      return True
    # if (datetimeObj.date() == holidays.dt.date[11]):
    #   return True
    else:
      return False
  
# print((getHolidays()))
def expiryDay(datetimeObj):
    ''' Important
    For Linux Replace # in ("%y%#m%d") with -
    Also do for monthly expiry'''
    iso_day = datetimeObj.isoweekday()
    days_to_exp= (4 - iso_day) if iso_day <=4 else (11-datetimeObj.isoweekday())
    
    # print('Day is :',datetimeObj.day,' Days to expiry : ',days_to_exp)
    exp_day= datetimeObj+timedelta(days=days_to_exp)
    # return exp_day
    while(isHoliday(exp_day)==True):
        exp_day=exp_day - timedelta(days=1)
    return exp_day.date()

def optionSymbol(name,instrument_type,strike=None,datetimeObj=None):
    if instrument_type == 'CE' or instrument_type == 'PE':
        exp_day = expiryDay(datetimeObj)
        instruments = pd.read_csv('instruments.csv')
        instruments['expiry'] = pd.to_datetime(instruments['expiry'])
        symbol=instruments[(instruments['expiry'].dt.date==exp_day) & (instruments['name']==name) & (instruments['strike']==strike) &( instruments['instrument_type']==instrument_type)]
        return symbol['instrument_token'].values[0],symbol['tradingsymbol'].values[0],symbol['exchange'].values[0]
    if instrument_type == 'EQ':
        instruments = pd.read_csv('instruments.csv')
        symbol=instruments[ (instruments['name']==name) & ( instruments['instrument_type']==instrument_type)]
        return (symbol['instrument_token'].values[0],symbol['tradingsymbol'].values[0],symbol['exchange'].values[0],symbol['exchange'].values[0]+':'+symbol['tradingsymbol'].values[0])
        # return (symbol['instrument_token'].values,symbol['tradingsymbol'].values,symbol['exchange'].values,symbol['exchange'].values+':'+symbol['tradingsymbol'].values)
    '''if instrument_type == 'FUT':
        exp_day = expiryDay(datetimeObj)
        instruments = pd.read_csv('instruments.csv')
        instruments['expiry'] = pd.to_datetime(instruments['expiry'])
        symbol=instruments[(instruments['expiry'].dt.date==exp_day) & (instruments['name']==name) & (instruments['strike']==strike) &( instruments['instrument_type']==instrument_type)]
        return symbol['instrument_token'].values[0],symbol['tradingsymbol'].values[0],symbol['exchange'].values[0]
        '''
        



# dat =datetime.now()# + timedelta(days=25)
# # print((expiryDay(dat)))
# print(optionSymbol('NIFTY','CE',17150,dat))
# print(optionSymbol('ITC','EQ'))
# x=optionSymbol('ITC','EQ')
# print(x[0])
# print(isHoliday(weeklyExpiry(dat)))

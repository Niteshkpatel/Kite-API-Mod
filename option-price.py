from optionprice import Option

x = Option(european=True,
                    kind='call',
                    s0=17400,
                    k=17400,
                    t=3,
                    sigma=0.1125,
                    r=0.1,
                    dv=0)
# print(x)
price=round(x.getPrice(),2)
print(price)
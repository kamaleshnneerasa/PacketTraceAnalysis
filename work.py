import math
import numpy as np
import pandas as pd

tb = pd.read_csv('lbnl.anon-ftp.03-01-14.csv')

tcp = tb[tb['Protocol']=='TCP']
tcpsyn = tcp[tcp['Info'].str.find('[SYN]')>-1] 

tcpsyn1 = tcpsyn

tcpsyn = tcpsyn.sort_values('Source', ascending=False)
tcpsyn = tcpsyn.drop_duplicates(subset ='Source', keep = 'first') 

tcpsyn1 = tcpsyn1.sort_values('Destination', ascending=False)
tcpsyn1 = tcpsyn1.drop_duplicates(subset ='Destination', keep = 'first')

sources = tcpsyn['Source'].to_list() 
destinatns = tcpsyn1['Destination'].to_list()  


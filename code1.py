import math
import numpy as np
import pandas as pd

tb11 = pd.read_csv('lbnl.anon-ftp.03-01-11.csv');

tb11_tcp = tb11[tb11['Protocol']=='TCP']

tb11_tcpsyn = tb11_tcp[tb11_tcp['Info'].str.find('[SYN]')>-1] 

# tb11_tcpsyn.to_csv('q1.csv')
tb11_tcpsyn1 = tb11_tcpsyn

tb11_tcpsyn = tb11_tcpsyn.sort_values('Source', ascending=False)
tb11_tcpsyn = tb11_tcpsyn.drop_duplicates(subset ='Source', keep = 'first') 

tb11_tcpsyn1 = tb11_tcpsyn1.sort_values('Destination', ascending=False)
tb11_tcpsyn1 = tb11_tcpsyn1.drop_duplicates(subset ='Destination', keep = 'first')  

tb11_tcpsyn.to_csv('q1_sources.csv')

tb11_tcpsyn.to_csv('q1_dsns.csv')
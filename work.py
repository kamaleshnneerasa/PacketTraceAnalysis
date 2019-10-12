import math
import numpy as np
import pandas as pd

#tb11 = pd.read_csv('lbnl.anon-ftp.03-01-11.csv');
tb14 = pd.read_csv('lbnl.anon-ftp.03-01-14.csv');
#tb18 = pd.read_csv('lbnl.anon-ftp.03-01-18.csv');

tb14_tcp = tb14[tb14['Protocol']=='TCP']
tb14_tcpsyn = tb14_tcp[tb14_tcp['Info'].str.find('[SYN]')>-1] 

tb14_tcpsyn1 = tb14_tcpsyn

tb14_tcpsyn = tb14_tcpsyn.sort_values('Source', ascending=False)
tb14_tcpsyn = tb14_tcpsyn.drop_duplicates(subset ='Source', keep = 'first') 

tb14_tcpsyn1 = tb14_tcpsyn1.sort_values('Destination', ascending=False)
tb14_tcpsyn1 = tb14_tcpsyn1.drop_duplicates(subset ='Destination', keep = 'first')

tb14_sources = tb14_tcpsyn['Source'].to_list() 
tb14_destinatns = tb14_tcpsyn1['Destination'].to_list()  
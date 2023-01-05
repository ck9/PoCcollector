import re, os, sys
thisPath = os.path.dirname(__file__)
sys.path.append(os.path.join(thisPath, 'src'))
from functions import *

sign = input('Enter Signature: ')

print ("\n"+signSearch(sign))
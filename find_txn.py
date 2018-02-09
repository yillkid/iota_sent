# coding=utf-8
from iota import Iota
from config_iota_wallet import NODE_URL, SEED

api = Iota(NODE_URL, SEED)
dict_txn = api.find_transactions(tags = ['HAHAHOHOHO'])

print "The tag NTCTODAY transaction hash: " + str(dict_txn['hashes'])

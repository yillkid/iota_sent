# coding=utf-8
from iota import Iota
from config_iota_wallet import NODE_URL, SEED

api = Iota(NODE_URL, SEED)
dict_addr = api.get_new_addresses(count = None, index = None)

print("New address: " + str(dict_addr['addresses']))

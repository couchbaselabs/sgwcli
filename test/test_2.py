#!/usr/bin/env python3

import warnings
from lib.cbsync import cb_connect_s

warnings.filterwarnings("ignore")


def test_cb_driver_1(hostname, bucket):
    field = "store_id"
    keyspace = "employees"

    query = f"select distinct {field} from {keyspace} where {field} is not missing;"
    db = cb_connect_s(hostname, "Administrator", "password", ssl=False).init()
    results = db.cb_query(sql=query)
    for record in results:
        value = record[field]
        assert 1 <= int(value) <= 3

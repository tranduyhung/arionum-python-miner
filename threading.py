import argon2
import argparse
import base64
import hashlib
import math
import threading
import multiprocessing
import os
import random
import re
import http.client
import urllib.parse
from datetime import datetime
import time
import json
import signal
signal.signal(signal.SIGINT, signal.SIG_DFL)

POOL_URL = "aro.cool"
WALLET_ADDRESS = ""
WORKER_NAME = hashlib.sha224((os.uname()[1]).encode("utf-8")).hexdigest()[0:32]
WORKER_QUANTITY = math.ceil((multiprocessing.cpu_count() + 1) / 2)
HASH_RATE_INTERVAL = 20
SUBMITTED_NONCES = 0
FAILED_NONCES = 0;
LAST_UPDATE = ""
DATE_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
HASH_RATES = []
REST = 0

# Work and info from pool
BLOCK = ""
DIFFICULTY = 0
LIMIT = 0
POOL_ADDRESS = ""
HEIGHT = ""

def update_work():
    global HEIGHT
    global LAST_UPDATE
    global WORKER_NAME
    global WALLET_ADDRESS
    global HASH_RATES
    global POOL_URL
    global BLOCK
    global DIFFICULTY
    global LIMIT
    global POOL_ADDRESS

    try:
        params = {
            "q": "info",
            "worker": WORKER_NAME,
            "address": WALLET_ADDRESS,
            "hashrate": sum(HASH_RATES)
        }

        params = urllib.parse.urlencode(params)
        c = http.client.HTTPConnection(POOL_URL, 80)
        c.request("GET", "/mine.php?" + params)
        r = c.getresponse()
        json_response = r.read().decode()
        data = json.loads(json_response)
        data = data["data"]
        c.close()

        if data is None:
            raise ValueError("data=None")

        block = data["block"]

        if block is None:
            raise ValueError("block=None")

        height = data["height"]

        if height is None:
            raise ValueError("height=None")

        difficulty = data["difficulty"]

        if difficulty is None:
            raise ValueError("difficulty=None")

        limit = data["limit"]

        if limit is None:
            raise ValueError("limit=None")

        pool_address = data["public_key"]

        if pool_address is None:
            raise ValueError("public_key=None")

        if height != HEIGHT:
            BLOCK = block
            DIFFICULTY = difficulty
            LIMIT = limit
            POOL_ADDRESS = pool_address
            HEIGHT = height

        print("Current block is %s, difficulty %s" % (HEIGHT, DIFFICULTY))
        LAST_UPDATE = datetime.now()
    except Exception as e:
        print("Failed to update work, retry in 5s:\n", e)
        time.sleep(5)

class Worker (threading.Thread):
    def __init__(self, id):
        threading.Thread.__init__(self)
        self.id = id

    def update_work(self):
        global LAST_UPDATE
        global DATE_TIME_FORMAT

        last_update = LAST_UPDATE
        now = datetime.now()

        now = datetime.strptime(now.strftime(DATE_TIME_FORMAT), DATE_TIME_FORMAT)
        last_update = datetime.strptime(last_update.strftime(DATE_TIME_FORMAT), DATE_TIME_FORMAT)

        now = time.mktime(now.timetuple())
        last_update = time.mktime(last_update.timetuple())

        diff = int(now - last_update) / 60

        if diff > 0.5:
            update_work()

    def solve_work(self):
        global POOL_URL
        global BLOCK
        global DIFFICULTY
        global HASH_RATE_INTERVAL
        global HASH_RATES
        global SUBMITTED_NONCES
        global FAILED_NONCES
        global REST

        work_count = 0
        time_start = time.time()

        while (True):
            nonce = base64.b64encode(random.getrandbits(256).to_bytes(32, byteorder='big')).decode('utf-8')
            nonce = re.sub('[^a-zA-Z0-9]', '', nonce)

            base = '%s-%s-%s-%s' % (POOL_ADDRESS, nonce, BLOCK, DIFFICULTY)

            ph = argon2.PasswordHasher(time_cost=1, memory_cost=524288, parallelism=1, hash_len=32)

            argon = ph.hash(base)
            base = base + argon
            hash = hashlib.sha512(base.encode('utf-8'))

            for i in range(4):
                hash = hashlib.sha512(hash.digest())

            digest = hashlib.sha512(hash.digest()).hexdigest()
            m = [digest[i:i + 2] for i in range(0, len(digest), 2)]
            duration = '%d%d%d%d%d%d%d%d' % (int(m[10], 16), int(m[15], 16),
                                             int(m[20], 16), int(m[23], 16),
                                             int(m[31], 16), int(m[40], 16),
                                             int(m[45], 16), int(m[55], 16))
            result = int(duration) // int(DIFFICULTY)

            if result > 0 and result <= LIMIT:
                print("Worker #%d found a valid nonce" % (self.id))
                self.submit_nonce(nonce, argon, POOL_ADDRESS)

            work_count += 1
            time_end = time.time()
            HASH_RATES[self.id] = work_count / (time_end - time_start)

            if work_count == HASH_RATE_INTERVAL:
                work_count = 0
                time_start = time_end

                if self.id == 0:
                    print('%.2f H/s - %d worker(s) - %d/%d nonce(s) submitted successfully'
                        % (sum(HASH_RATES),
                            len(HASH_RATES),
                            SUBMITTED_NONCES,
                            SUBMITTED_NONCES + FAILED_NONCES))

            if REST > 0:
                time.sleep(REST)

            if self.id == 0:
                self.update_work()

    def submit_nonce(self, nonce, argon, pool_address):
        global POOL_URL
        global WALLET_ADDRESS
        global SUBMITTED_NONCES
        global FAILED_NONCES

        argon = argon[30:]
        print("Submitting nonce:")
        print(" - nonce: %s" % (nonce))
        print(" - argon: %s" % (argon))

        params = {
            "argon": argon,
            "nonce": nonce,
            "private_key": WALLET_ADDRESS,
            "public_key": pool_address,
            "address": WALLET_ADDRESS,
        }

        body = urllib.parse.urlencode(params)

        headers = {
            "Content-Type": "application/x-www-form-urlencoded;"
        }

        c = http.client.HTTPConnection(POOL_URL, 80)
        c.request('POST', '/mine.php?q=submitNonce', body, headers)
        r = c.getresponse()
        json_response = r.read().decode()
        c.close()

        data = json.loads(json_response)

        if "data" in data:
            data = data["data"]

            if data == "accepted":
                print("Submitted nonce successfully")
                SUBMITTED_NONCES += 1
            else:
                print("Failed to submit nonce:\n", data)
                FAILED_NONCES += 1
        else:
            print("Unknown response from pool:\n", json_response)

    def run(self):
        while True:
            self.solve_work()

def main():
    global POOL_URL
    global WALLET_ADDRESS
    global WORKER_NAME
    global WORKER_QUANTITY
    global HASH_RATE_INTERVAL
    global HASH_RATES
    global REST

    parser = argparse.ArgumentParser(description="Arionum Python Miner")

    parser.add_argument(
        "--config",
        type=str,
        default="config.json",
        help="JSON config file")

    args = parser.parse_args()
    config_file = "config.json"

    if args.config is not None and args.config != "":
        config_file = args.config

    try:
        f = open(config_file, "r")
        config = f.read()
        f.close()
        config = json.loads(config)
    except Exception as e:
        print(e)
        exit()

    if "pool" in config:
        POOL_URL = config["pool"]

    if "wallet_address" in config:
        WALLET_ADDRESS = config["wallet_address"]

    if "worker_name" in config and config["worker_name"] != "":
        WORKER_NAME = config["worker_name"]

    if "worker_quantity" in config:
        worker_quantity = config["worker_quantity"]

        try:
            worker_quantity += 1
        except TypeError:
            print("worker_quantity must be an integer")
            exit()

        if config["worker_quantity"] > 0:
            WORKER_QUANTITY = config["worker_quantity"]

    if "hash_rate_interval" in config:
        hash_rate_interval = config["hash_rate_interval"]
        
        try:
            hash_rate_interval += 1
        except TypeError:
            print("hash_rate_interval must be an integer")
            exit()
 
        if config["hash_rate_interval"] > 0:
            HASH_RATE_INTERVAL =  config["hash_rate_interval"]

    if "rest" in config:
        rest = config["rest"]

        try:
            rest += 1
        except TypeError:
            print("rest must be an integer or a float")
            exit()

        if config["rest"] > 0:
            REST = config["rest"]

    if WALLET_ADDRESS == "":
        print("Please provide your wallet address")
        exit()

    print("Wallet: %s" % (WALLET_ADDRESS))
    print("Pool: %s" % (POOL_URL))
    print("Worker name: %s" % (WORKER_NAME))
    print("Worker quantity: %s" % (WORKER_QUANTITY))
    print("Show hash rate: every %s work(s)" % (HASH_RATE_INTERVAL))
    print("Rest: %s second(s)" % (REST))
    print("Miner is running with PID %d" % (os.getpid()))

    update_work()
    workers = []

    for i in range(WORKER_QUANTITY):
        worker = Worker(i)
        HASH_RATES.append(0)

        worker.start()
        print("Worker #%d started" % (i))
        workers.append(worker)

    for worker in workers:
        worker.join()

if __name__ == '__main__':
    main()

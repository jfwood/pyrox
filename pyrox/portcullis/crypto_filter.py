import pyrox.filtering as filtering

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
import requests


class CryptoFilter(filtering.HttpFilter):
    """
    This filter encrypts/decrypts data streamed through it on its way
    to/from a Swift encrypted volume.
    """
    REQUEST = 0
    RESPONSE = 1

    def __init__(self):
        super(CryptoFilter, self).__init__()
        print("initing new filter")

        #TODO(jwood) Just need one of these processors.
        self.processor_upload = SampleCryptoProcessor(is_encrypt=True)
        self.processor_download = SampleCryptoProcessor(is_encrypt=False)
        self.request_method = None
        self.hmac = HMAC.new("secretkey", digestmod=SHA256.new())

    @filtering.handles_request_head
    def on_request_head(self, request_head):
        print(">>>>>>> {}".format(self))
        print('Got request head with verb: {}'.format(request_head.method))
        self.request_method = request_head.method
        self.url = request_head.url
        self.auth_token = request_head.header("X-Auth-Token").values[0]

    @filtering.handles_response_head
    def on_response_head(self, response_head):
        print('Got response head with status: {}'.format(response_head.status))
        if response_head.status == '201' and self.request_method == 'PUT':
            self.set_hmac()
        hmac_digest = response_head.get_header("X-Object-Meta-Hmac-Digest")
        if hmac_digest:
            self.hmac_digest = hmac_digest.values[0]

    @filtering.handles_request_body
    def on_request_body(self, msg_part, output):
        """Must be able to handle the following conditions:
        1) The input is exactly the same size as modulo-block-size blocks of
           post-processed buffer output, so can send these along to the upstream server.
        2) The input data is not enough to create an output block, so can't send
           anything along to upstream yet.
        3) The input data is not an even block size, so can only send some
           blocks along to upstream (leaving some data in the buffer).
        4) The input data is empty/None indicating no more data to send along
           so need to send all final block(s) along to upstream.
        """
        # print('Got request content chunk: {}'.format(msg_part))
        # output.write(msg_part)

        print(">>>>>>>>>>>>>>>>>>>> req_body - req method: {}".format(self.request_method))

        if not self.request_method == 'PUT':
            output.write(msg_part)
            return

        self.process_chunk(msg_part, self.REQUEST, output)

    @filtering.handles_response_body
    def on_response_body(self, msg_part, output):
        print('Got response content chunk')  # : {}'.format(msg_part))
        print(">>>>>>>>>>>>>>>>>>>> resp_body - req method: {}".format(self.request_method))

        if not self.request_method == 'GET':
            output.write(msg_part)
            return

        self.process_chunk(msg_part, self.RESPONSE, output)

    def process_chunk(self, msg_part, req_resp, output):
        if msg_part:
            if req_resp == self.REQUEST:
                output_part = self.processor_upload.process_data(msg_part)
                self.hmac.update(output_part)
            else:
                self.hmac.update(msg_part)
                output_part = self.processor_download.process_data(msg_part)
            if output_part:
                print("!!!!! Output chunk...message length {}".format(len(msg_part)))  # .format(output_part))
                output.write(output_part)
            else:
                print("!!!!! Not enough data for message length {}".format(len(msg_part)))
                output.write("")
        else:
            if req_resp == self.REQUEST:
                print('finishing request')
                output_part = self.processor_upload.finish()
            else:
                print('finishing response')
                output_part = self.processor_download.finish()
                # this stuff isn't being invoked right now
                print('done downloading. hmac should be {}'.format(self.hmac_digest))
                print('done downloading. hmac is {}'.format(self.hmac.hexdigest()))
            print("!!!!! Final: {}".format(output_part))
            output.write(output_part)

    def set_hmac(self):
        print("!!!!! start set hmac")
        url = "https://storage101.dfw1.clouddrive.com:443" + self.url
        headers = {"X-Object-Meta-Hmac-Digest": self.hmac.hexdigest(),
                   "X-Auth-Token": self.auth_token}
        requests.post(url, headers=headers)
        print("!!!!! end set hmac")



#TODO(jwood) Consider adding a base Processor class, that this one extends?
class SampleCryptoProcessor(object):
    def __init__(self, is_encrypt, block_size_bytes=16):
        self.block_size_bytes = block_size_bytes
        key = 'sixteen_byte_key'
        iv = 'sixteen_byte_iv!'
        self.block_method = self._encrypt_block if is_encrypt else self._decrypt_block
        self.encryptor = AES.new(key, AES.MODE_CBC, iv)
        self.decryptor = AES.new(key, AES.MODE_CBC, iv)
        self.last_block = ''
        self.is_encrypt = is_encrypt

    def process_data(self, data):
        """Accept and process the input 'data' block. Return an 'output' that
        is a modulo of this processor's block size, which may not be evenly
        aligned with the input data's size.
        """
        buff = ''.join([self.last_block, data])
        len_buff = len(buff)
        if len_buff <= self.block_size_bytes:
            self.last_block = buff
            return ''

        len_buff_modulo = len_buff - (len_buff % self.block_size_bytes)
        if not len_buff % self.block_size_bytes:
            len_buff_modulo -= self.block_size_bytes
        self.last_block = buff[len_buff_modulo:]
        output = self.block_method(buff[:len_buff_modulo])
        return output

    def finish(self):
        """Indicate that we are finished using this data structure, so need to output based on existing buffer data."""
        if self.is_encrypt:
            output = self._pad(self.last_block)
            output = self.block_method(output)
        else:
            output = self.block_method(self.last_block)
            output = self._strip_pad(output)
        self.last_block = ''
        return output

    def _encrypt_block(self, block):
        block = self.encryptor.encrypt(block)
        return block

    def _decrypt_block(self, block):
        return self.decryptor.decrypt(block)

    def _pad(self, unencrypted):
        """Adds padding to unencrypted byte string."""
        pad_length = self.block_size_bytes - (
            len(unencrypted) % self.block_size_bytes
        )
        return unencrypted + (chr(pad_length) * pad_length)

    def _strip_pad(self, unencrypted):
        pad_length = ord(unencrypted[-1:])
        unpadded = unencrypted[:-pad_length]
        return unpadded

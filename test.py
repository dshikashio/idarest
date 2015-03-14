import unittest
import urllib2
import urllib
import requests
import json

BASE_URL = 'http://localhost:8899/ida/api/v1.0'

class HttpTestCase(unittest.TestCase):
    def setUp(self):
        self.url = BASE_URL + '/cursor'

    def _check_json_codes(self, r):
        self.assertEqual(r.headers['content-type'], 'application/json')
        response = r.json()
        self.assertTrue('code' in response, "missing code from response")
        self.assertEqual(response['code'], 200)
        self.assertTrue('msg' in response, "missing msg from response")

    def test_get(self):
        r = requests.get(self.url)
        self.assertEqual(r.status_code, 200, "bad status code on generic GET")
        self._check_json_codes(r)

    def test_post(self):
        r = requests.post(self.url)
        self.assertEqual(r.status_code, 200, "bad status code on generic POST")
        self._check_json_codes(r)

    def test_get_invalid_url(self):
        r = requests.get(BASE_URL + '/bad_api')
        self.assertEqual(r.status_code, 404, "failed to detect invalid api URL")

    def test_post_invalid_url(self):
        r = requests.post(BASE_URL + '/bad_api')
        self.assertEqual(r.status_code, 404, "failed to detect invalid api URL")

    def test_post_bad_content_type(self):
        r = requests.post(self.url, data={'ea' : '0x8888'})
        self.assertEqual(r.status_code, 400, "failed to detect bad content-type")

    def test_multiple_instance_of_param(self):
        r = requests.get(self.url + '?ea=0x93232&ea=0x8888')
        self.assertEqual(r.status_code, 400,
                "failed to multiple instances of 1 param")

    def test_post_json_invalid(self):
        headers = {'content-type': 'application/json'}
        r = requests.post(self.url,
                data=json.dumps({'ea' : '0x8888'})+'foo}}}{{',
                headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 400, "failed to detect invalid json POST")

    def test_post_json(self):
        r = requests.post(self.url, data=json.dumps({'ea' : '0x8888'}))
        self.assertEqual(r.status_code, 200, "failed to POST json")

    def _verify_jsonp(self, r):
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers['content-type'], 'application/javascript')
        self.assertTrue(r.text.startswith('foobar('))
        self.assertTrue(r.text.endswith(');'))

    def test_post_jsonp_response(self):
        r = requests.post(self.url, params={'callback': 'foobar'})
        self._verify_jsonp(r)

    def test_get_jsonp_response(self):
        r = requests.get(self.url, params={'callback': 'foobar'})
        self._verify_jsonp(r)


class CursorTestCase(unittest.TestCase):
    def setUp(self):
        self.url = BASE_URL + '/cursor'

    def _check_json_codes(self, r):
        self.assertEqual(r.headers['content-type'], 'application/json')
        response = r.json()
        self.assertTrue('code' in response, "missing code from response")
        self.assertEqual(response['code'], 200)
        self.assertTrue('msg' in response, "missing msg from response")

    def test_get_cursor(self):
        r = requests.get(self.url)
        self._check_json_codes(r)

    def test_set_cursor(self):
        r = requests.get(self.url, params={'ea': '0x67a82'})
        response = r.json()
        self.assertEqual(response['code'], 200)

    def test_set_invalid_cursor(self):
        r = requests.get(self.url, params={'ea': 'hhhhhh'})
        response = r.json()
        self.assertEqual(response['code'], 400)

class SegmentsTestCase(unittest.TestCase):
    def setUp(self):
        self.url = BASE_URL + '/segments'

    def test_get_all_segments(self):
        self.fail()

    def test_get_segment_by_address(self):
        self.fail()

class NamesTestCase(unittest.TestCase):
    def setUp(self):
        self.url = BASE_URL + '/names'

    def test_get_names(self):
        self.fail()

class ColorTestCase(unittest.TestCase):
    def setUp(self):
        self.url = BASE_URL + '/color'

    def test_get_address_color(self):
        self.fail()

    def test_set_address_color(self):
        self.fail()


if __name__ == '__main__':
    unittest.main()

import requests
import time
import hashlib
import fold_challenge


def md5(s):
    return hashlib.md5(s.encode('utf-8')).hexdigest()


def transaction_signature(sitekey, mail):
    return 'TH[' + md5(sitekey + mail) + ']'


class MTCaptcha:

    def __init__(self, sitekey, hostname):
        self.sitekey = sitekey
        self.hostname = hostname
        self.lf = '1'
        self.lang = 'sv'

    def get_challenge(self, session_id: str) -> dict:
        # 'sk': _0x281455.sitekey,
        # 'bd': _0x281455.hostname,
        # 'rt': Math.floor(Date.now()),
        # 'tsh': _0x235f09.hash.generate.transactionSignature(_0x281455.sitekey, 'mtcap@mtcaptcha.com') || '$',
        # 'act': _0x281455.action || '$',
        # 'ss': _0x281455.sessionID,
        # 'lf': _0x281455.lf,
        # 'tl': _0x281455.textLength != 0x0 ? _0x281455.textLength : '$',
        # 'lg': _0x281455.lang,
        # 'tp': _0x281455.widgetSize == _0x235f09.constant.standard ? 's' : 'm'

        params = {
            'sk': self.sitekey,
            'bd': self.hostname,
            'rt': int(time.time()),
            'tsh': transaction_signature(self.sitekey, 'mtcap@mtcaptcha.com'),
            'act': '$',
            'ss': session_id,
            'lf': self.lf,
            'tl': '$',
            'lg': self.lang,
            'tp': 's'
        }

        r = requests.get(
            'https://service.mtcaptcha.com/mtcv1/api/getchallenge.json', params=params)

        return r.json()['result']['challenge']

    def get_image(self, session_id: str, challenge: dict) -> str:
        # 'sk': _0x2ce69d.sitekey,
        # 'ct': _0x2ce69d.ct,
        # 'fa': _0x2ce69d.fa || '$',
        # 'ss': _0x2ce69d.sessionID

        ct = challenge['ct']

        # _0x37031b.fa = _0x37031b.hasFoldChlg && _0x37031b.foldChlg.preRes ? _0x235f09.FoldChlg.solve(_0x37031b.foldChlg.fseed, _0x37031b.foldChlg.fslots, _0x37031b.foldChlg.fdepth) : '$';

        if challenge['hasFoldChlg'] and challenge['foldChlg']['preRes']:
            fa = fold_challenge.solve(
                challenge['foldChlg']['fseed'], challenge['foldChlg']['fslots'], challenge['foldChlg']['fdepth'])
        else:
            fa = '$'

        params = {
            'sk': self.sitekey,
            'ct': ct,
            'fa': fa,
            'ss': session_id
        }

        r = requests.get('https://service.mtcaptcha.com/mtcv1/api/getimage.json', params=params)
        # there is a wait delay sometimes, need to implement handling for that

        return r.json()['result']['img']['image64']


#sitekey = 'MTPublic-CVBtYUW2o'
#hostname = 'bokapass.nemoq.se'
#sessionID = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' # you need to find it yourself
#
#api = MTCaptcha(sitekey, hostname)
#
#challenge = api.get_challenge(sessionID)
#
#print(challenge)
#print(api.get_image(sessionID, challenge))
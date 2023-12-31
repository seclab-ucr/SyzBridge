from syzbridge.modules.syzbot import Crawler

def get_case(hash_val, **kwargs):
    syzbot = Crawler(**kwargs)
    case = syzbot.run_one_case(hash_val)
    case['hash'] = hash_val
    return case

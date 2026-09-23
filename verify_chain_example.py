from pulpo_governance.audit.verify import verify_record
from pulpo_governance.audit.keys import get_verify_key_hex
import json, os

CHAIN_FILE = 'audit_chain.jsonl'
if not os.path.exists(CHAIN_FILE):
    print('No audit_chain.jsonl found.')
else:
    vk = get_verify_key_hex()
    with open(CHAIN_FILE,'r',encoding='utf-8') as f:
        for line in f:
            rec = json.loads(line)
            try:
                verify_record(rec, vk)
                print('Record', rec['id'], 'signature valid')
            except Exception as e:
                print('Record', rec['id'], 'verification failed:', e)

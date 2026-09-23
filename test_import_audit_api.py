import importlib, traceback, sys
try:
    importlib.import_module('pulpo_governance.api.audit_api')
    print('pulpo_governance.api.audit_api import ok')
except Exception:
    traceback.print_exc()
    sys.exit(1)

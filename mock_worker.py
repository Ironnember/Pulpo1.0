from fastapi import FastAPI
from pydantic import BaseModel
import time, hashlib, uvicorn

app = FastAPI()

class ExecuteRequest(BaseModel):
    permit_id: str
    capability: str
    payload: dict

@app.post('/execute')
def execute(req: ExecuteRequest):
    start = time.time()
    prompt = req.payload.get('prompt','hello')
    time.sleep(0.2)
    result = f'echo: {prompt}'
    duration_ms = int((time.time() - start) * 1000)
    metadata = {
        'worker_id': 'mock-worker-1',
        'capability': req.capability,
        'model': req.payload.get('model_id'),
        'duration_ms': duration_ms,
        'tokens_in': len(str(prompt).split()),
        'tokens_out': len(str(result).split())
    }
    result_hash = 'sha256:' + hashlib.sha256(result.encode()).hexdigest()
    return {'result': result, 'metadata': metadata, 'evidence': {'hash': result_hash, 'timestamp': time.time()}}
    
if __name__ == '__main__':
    uvicorn.run(app, host='127.0.0.1', port=9001)

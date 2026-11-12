import unittest, asyncio, hashlib, tracemalloc, time, json
from pulpo_p3.framing import Frame, FrameDecoder, FrameError, HEADER, MAGIC, VERSION, MAX_PAYLOAD, encode_frame
from pulpo_p3.flow import BoundedIngress, BackpressureError
from pulpo_p3.tcp import TCPReceiver, TCPSettings

class ParserSecurityTests(unittest.TestCase):
    def test_oversized_header_rejected_without_payload_allocation(self):
        decoder=FrameDecoder()
        for length in (MAX_PAYLOAD+1, 2**32-1):
            with self.assertRaises(FrameError): decoder.feed(HEADER.pack(MAGIC,VERSION,0,1,1,length,b'0'*32))
            self.assertEqual(0,decoder.pending_bytes)

    def test_fragmented_maximum_frame_and_truncated_eof(self):
        raw=encode_frame(Frame(1,1,b'x'*MAX_PAYLOAD)); decoder=FrameDecoder()
        for p in range(0,len(raw)-1,4096):
            end=min(p+4096,len(raw)-1)
            decoder.feed(raw[p:end]); self.assertLessEqual(decoder.pending_bytes,decoder.max_buffer)
        self.assertEqual(1,len(decoder.feed(raw[-1:])))
        decoder.feed(raw[:HEADER.size+128])
        with self.assertRaises(FrameError): decoder.finish()
        self.assertEqual(0,decoder.pending_bytes)

    def test_bad_digest_releases_buffer(self):
        raw=encode_frame(Frame(1,1,b'hello'))
        decoder=FrameDecoder()
        with self.assertRaises(FrameError): decoder.feed(raw[:-1]+b'x')
        self.assertEqual(0,decoder.pending_bytes)

    def test_amplified_small_frames_bounded_input_records_output_cost(self):
        # feed returns all completed frames in one list; measure this explicitly.
        raw=encode_frame(Frame(1,1,b''))*10000
        tracemalloc.start(); started=time.perf_counter()
        decoder=FrameDecoder(); frames=decoder.feed(raw)
        current,peak=tracemalloc.get_traced_memory(); tracemalloc.stop()
        print('P3_COALESCED '+json.dumps({'input_bytes':len(raw),'output_frames':len(frames),'traced_peak_bytes':peak,'wall_seconds':time.perf_counter()-started}))
        self.assertEqual(10000,len(frames)); self.assertEqual(0,decoder.pending_bytes)

    def test_handoff_rejects_frame_count_and_byte_exhaustion(self):
        ingress=BoundedIngress(4,max_bytes=1024)
        for i in range(4): ingress.offer(Frame(1,i,b'x'*256))
        for i in range(1000):
            with self.assertRaises(BackpressureError): ingress.offer(Frame(1,i,b'x'))
        self.assertEqual(1024,ingress.retained_bytes); self.assertEqual(4,len(ingress))
        while ingress.take_for_existing_router() is not None: pass
        self.assertEqual(0,ingress.retained_bytes)

class LiveLoopbackSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.receiver=TCPReceiver(TCPSettings(host='127.0.0.1',port=0,max_connections=2,max_frames=4,max_bytes=1024,max_payload=256,frame_timeout=.2))
        await self.receiver.start(); self.address=self.receiver.address; self.writers=[]
    async def connect(self):
        r,w=await asyncio.open_connection(*self.address); self.writers.append(w); return r,w
    async def asyncTearDown(self):
        for w in self.writers:
            w.close()
            try: await w.wait_closed()
            except (ConnectionError,OSError): pass
        await self.receiver.close()
        s=self.receiver.snapshot(); print('P3_CLEANUP '+json.dumps(s))
        self.assertEqual(0,s['active_connections']); self.assertEqual(0,s['pending_frames']); self.assertEqual(0,s['retained_payload_bytes'])
        self.assertFalse(self.receiver._server.is_serving()); self.assertTrue(all(t.done() for t in self.receiver._tasks))
    async def test_oversized_tcp_header_closes_before_body(self):
        r,w=await self.connect(); w.write(HEADER.pack(MAGIC,VERSION,0,1,1,2**32-1,b'0'*32)); await w.drain()
        self.assertEqual(b'',await asyncio.wait_for(r.read(),1))
        self.assertEqual(1,self.receiver.snapshot()['invalid'])
    async def test_slow_partial_header_and_connection_limit(self):
        r1,w1=await self.connect(); r2,w2=await self.connect(); await asyncio.sleep(.02)
        r3,w3=await self.connect(); self.assertEqual(b'',await asyncio.wait_for(r3.read(),1))
        w1.write(b'P'); w2.write(b'P3'); await w1.drain(); await w2.drain()
        await asyncio.sleep(.3)
        s=self.receiver.snapshot(); print('P3_SLOW '+json.dumps(s))
        self.assertGreaterEqual(s['connections_rejected'],1); self.assertEqual(2,s['timed_out']); self.assertEqual(0,s['active_connections'])
    async def test_flood_queue_exhaustion_closes_and_preserves_bounds(self):
        r,w=await self.connect()
        w.write(b''.join(encode_frame(Frame(1,i,b'x'*256)) for i in range(20))); await w.drain()
        self.assertEqual(b'',await asyncio.wait_for(r.read(),1))
        s=self.receiver.snapshot(); print('P3_FLOOD '+json.dumps(s))
        self.assertEqual(4,s['pending_frames']); self.assertEqual(1024,s['retained_payload_bytes']); self.assertEqual(1,s['capacity_rejected'])

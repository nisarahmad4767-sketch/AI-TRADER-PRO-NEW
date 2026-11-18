import os,tempfile,unittest,importlib
from fastapi.testclient import TestClient
class PaperTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();os.environ['DB_PATH']=cls.tmp.name+'/test.sqlite3';os.environ['APP_PASSWORD']='unit-test-only';os.environ['SESSION_SECRET']='x'*40
  import app;cls.app=importlib.reload(app);cls.c=TestClient(cls.app.app)
  r=cls.c.post('/api/login',json={'password':'unit-test-only'});assert r.status_code==200
  cls.headers={'x-csrf-token':r.json()['csrf_token']}
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def test_01_auth(self):
  self.assertEqual(self.c.get('/api/paper',cookies={'paper_session':'invalid'}).status_code,401)
  self.assertEqual(self.c.post('/api/login',json={'password':'wrong'}).status_code,401)
 def test_018_login_rejects_non_json_media_type(self):
  import app
  with app.LOCK:
   saved=app.LOGIN_FAILURES.pop('testclient',None)
  try:
   for media_type in ('text/plain','application/x-www-form-urlencoded'):
    r=self.c.post('/api/login',content=b'{"password":"unit-test-only"}',headers={'content-type':media_type})
    self.assertEqual(r.status_code,415)
    self.assertNotIn('set-cookie',r.headers)
  finally:
   with app.LOCK:
    app.LOGIN_FAILURES.pop('testclient',None)
    if saved is not None:app.LOGIN_FAILURES['testclient']=saved

 def test_0185_streamed_login_payload_stops_after_limit(self):
  import app
  with app.LOCK:
   saved=app.LOGIN_FAILURES.pop('testclient',None)
  try:
   # TestClient buffers uploads, so assert rejection of a multi-chunk input.
   def chunks():
    yield b' ' * 4096
    yield b'x'
   r=self.c.post('/api/login',content=chunks(),headers={'content-type':'application/json'})
   self.assertEqual(r.status_code,413)
  finally:
   with app.LOCK:
    app.LOGIN_FAILURES.pop('testclient',None)
    if saved is not None:app.LOGIN_FAILURES['testclient']=saved

 def test_019_malformed_login_json_returns_400(self):
  r=self.c.post('/api/login',content=b'{bad',headers={'content-type':'application/json'})
  self.assertEqual(r.status_code,400)
  self.assertEqual(r.headers.get('cache-control'),'no-store')
 def test_01904_duplicate_login_password_rejected(self):
  r=self.c.post('/api/login',content=b'{"password":"wrong","password":"unit-test-only"}',headers={'content-type':'application/json'})
  self.assertEqual(r.status_code,400)
  self.assertNotIn('set-cookie',r.headers)
 def test_01905_non_object_login_json_rejected(self):
  # Login payload must be an object, not an array.
  payload=b'["unit-test-only"]'
  r=self.c.post('/api/login',content=payload,headers={'content-type':'application/json'})
  self.assertEqual(r.status_code,400)
  self.assertEqual(r.headers.get('cache-control'),'no-store')
 def test_01906_nonstring_password_rejected(self):
  import app
  ip='testclient'
  with app.LOCK:
   saved=app.LOGIN_FAILURES.pop(ip,None)
  try:
   for password in (None, 123, True, ['unit-test-only'], {'value':'unit-test-only'}):
    r=self.c.post('/api/login',json={'password':password})
    self.assertEqual(r.status_code,400)
    self.assertNotIn('set-cookie',r.headers)
  finally:
   with app.LOCK:
    app.LOGIN_FAILURES.pop(ip,None)
    if saved is not None:app.LOGIN_FAILURES[ip]=saved

 def test_019065_login_response_survives_concurrent_eviction(self):
  import app
  from unittest.mock import patch
  original=app.JSONResponse
  isolated=TestClient(app.app)
  def evict_before_response(*args,**kwargs):
   # Simulate another login evicting the just-created session.
   with app.LOCK:
    app.SESSIONS.clear()
    app.CSRF_TOKENS.clear()
   return original(*args,**kwargs)
  with app.LOCK:
   saved_sessions=app.SESSIONS.copy()
   saved_csrf=app.CSRF_TOKENS.copy()
  try:
   with patch.object(app,'JSONResponse',side_effect=evict_before_response):
    r=isolated.post('/api/login',json={'password':'unit-test-only'})
   self.assertEqual(r.status_code,200)
   self.assertTrue(r.json()['csrf_token'])
  finally:
   with app.LOCK:
    app.SESSIONS.clear();app.SESSIONS.update(saved_sessions)
    app.CSRF_TOKENS.clear();app.CSRF_TOKENS.update(saved_csrf)

 def test_01907_login_session_limit_evicts_oldest(self):
  import app
  original_cookie=self.c.cookies.get('paper_session')
  with app.LOCK:
   old_sessions=app.SESSIONS.copy()
   old_csrf=app.CSRF_TOKENS.copy()
   app.SESSIONS.clear();app.CSRF_TOKENS.clear()
   for i in range(32):
    app.SESSIONS[f'old-{i}']=10000000000+i
    app.CSRF_TOKENS[f'old-{i}']=f'csrf-{i}'
  try:
   r=self.c.post('/api/login',json={'password':'unit-test-only'})
   self.assertEqual(r.status_code,200)
   with app.LOCK:
    self.assertEqual(len(app.SESSIONS),32)
    self.assertNotIn('old-0',app.SESSIONS)
    self.assertNotIn('old-0',app.CSRF_TOKENS)
    self.assertIn('old-1',app.SESSIONS)
  finally:
   with app.LOCK:
    app.SESSIONS.clear();app.SESSIONS.update(old_sessions)
    app.CSRF_TOKENS.clear();app.CSRF_TOKENS.update(old_csrf)
   self.c.cookies.clear()
   if original_cookie is not None:self.c.cookies.set('paper_session',original_cookie)

 def test_0191_malformed_login_attempts_are_throttled(self):
  import app
  ip='testclient'
  with app.LOCK:
   saved=app.LOGIN_FAILURES.pop(ip,None)
  try:
   for _ in range(5):
    r=self.c.post('/api/login',content=b'{broken',headers={'content-type':'application/json'})
    self.assertEqual(r.status_code,400)
   r=self.c.post('/api/login',json={'password':'unit-test-only'})
   self.assertEqual(r.status_code,429)
  finally:
   with app.LOCK:
    app.LOGIN_FAILURES.pop(ip,None)
    if saved is not None:app.LOGIN_FAILURES[ip]=saved
 def test_0192_oversized_login_payload_rejected_and_throttled(self):
  import app
  ip='testclient'
  with app.LOCK:
   saved=app.LOGIN_FAILURES.pop(ip,None)
  try:
   for _ in range(5):
    r=self.c.post('/api/login',content=b' '*4097,headers={'content-type':'application/json'})
    self.assertEqual(r.status_code,413)
   self.assertEqual(self.c.post('/api/login',json={'password':'unit-test-only'}).status_code,429)
  finally:
   with app.LOCK:
    app.LOGIN_FAILURES.pop(ip,None)
    if saved is not None:app.LOGIN_FAILURES[ip]=saved
 def test_01925_missing_csrf_record_fails_closed(self):
  import app,time
  token='valid-session-without-csrf'
  with app.LOCK:
   app.SESSIONS[token]=time.time()+3600
   app.CSRF_TOKENS.pop(token,None)
  try:
   r=self.c.post('/api/paper/action',cookies={'paper_session':token},json={'action':'reset'})
   self.assertEqual(r.status_code,403)
  finally:
   with app.LOCK:app.SESSIONS.pop(token,None)

 def test_0193_successful_login_prunes_expired_sessions(self):
  import app,time
  original_cookie=self.c.cookies.get('paper_session')
  expired='expired-session-for-test'
  active='active-session-for-test'
  with app.LOCK:
   app.SESSIONS[expired]=time.time()-10
   app.CSRF_TOKENS[expired]='expired-csrf'
   app.SESSIONS[active]=time.time()+3600
   app.CSRF_TOKENS[active]='active-csrf'
  try:
   r=self.c.post('/api/login',json={'password':'unit-test-only'})
   self.assertEqual(r.status_code,200)
   with app.LOCK:
    self.assertNotIn(expired,app.SESSIONS)
    self.assertNotIn(expired,app.CSRF_TOKENS)
    self.assertIn(active,app.SESSIONS)
    self.assertIn(active,app.CSRF_TOKENS)
  finally:
   if original_cookie:
    self.c.cookies.clear()
    self.c.cookies.set('paper_session',original_cookie)
   with app.LOCK:
    app.SESSIONS.pop(expired,None);app.CSRF_TOKENS.pop(expired,None)
    app.SESSIONS.pop(active,None);app.CSRF_TOKENS.pop(active,None)
 def test_02_start_state(self):
  s=self.c.get('/api/paper',headers=self.headers).json();self.assertEqual(s['equity'],42);self.assertFalse(s['live_trading_enabled'])
 def test_03_risk_modes(self):
  for mode in ['defensive','smart','aggressive']:
   r=self.c.post('/api/paper/action',headers=self.headers,json={'action':'risk_mode','mode':mode});self.assertEqual(r.status_code,200);self.assertEqual(r.json()['risk_mode'],mode)
 def test_04_simulated_trades_and_persistence(self):
  self.c.post('/api/paper/action',headers=self.headers,json={'action':'start'})
  for _ in range(36):
   r=self.c.post('/api/paper/action',headers=self.headers,json={'action':'tick'});self.assertEqual(r.status_code,200)
  s=self.c.get('/api/paper',headers=self.headers).json();self.assertGreater(s['ticks'],0)
  trades=self.c.get('/api/paper/trades',headers=self.headers).json();self.assertGreater(len(trades),0)
  self.assertAlmostEqual(s['equity'],s['cash']+s['asset']*s['price'],places=3)
 def test_05_reset(self):
  s=self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).json();self.assertEqual(s['equity'],42);self.assertEqual(s['closed_trades'],0);self.assertEqual(s['ticks'],0);self.assertEqual(len(self.c.get('/api/paper/equity-history').json()),1)
 def test_06_invalid_action(self):
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'buy_live'}).status_code,400)
 def test_065_malformed_action_json_is_rejected_without_changes(self):
  import app
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)
  with app.LOCK:
   with app.connect() as db:
    before=db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
  r=self.c.post('/api/paper/action',headers={**self.headers,'content-type':'application/json'},content=b'{invalid')
  self.assertEqual(r.status_code,400)
  self.assertEqual(r.headers.get('cache-control'),'no-store')
  with app.LOCK:
   with app.connect() as db:
    self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0],before)

 def test_066_oversized_action_payload_does_not_write(self):
  import app
  with app.LOCK:
   with app.connect() as db:
    before=db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
  payload=b'{"action":"reset","padding":"'+b'x'*4096+b'"}'
  r=self.c.post('/api/paper/action',headers={**self.headers,'content-type':'application/json'},content=payload)
  self.assertEqual(r.status_code,413)
  self.assertEqual(r.headers.get('cache-control'),'no-store')
  with app.LOCK:
   with app.connect() as db:
    self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0],before)

 def test_07_public_safety(self):
  s=self.c.get('/api/status').json();self.assertFalse(s['binance_connected']);self.assertFalse(s['live_trading_enabled'])
 def test_08_csrf_protection(self):
  self.assertEqual(self.c.post('/api/paper/action',json={'action':'start'}).status_code,403)
  self.assertEqual(self.c.post('/api/paper/action',headers={**self.headers,'origin':'https://evil.example'},json={'action':'start'}).status_code,403)
 def test_09_history(self):
  self.c.post('/api/paper/action',headers=self.headers,json={'action':'start'})
  self.c.post('/api/paper/action',headers=self.headers,json={'action':'tick'})
  history=self.c.get('/api/paper/equity-history').json()
  self.assertGreaterEqual(len(history),2)
  self.assertAlmostEqual(history[-1]['equity'],self.c.get('/api/paper').json()['equity'],places=3)
 def test_095_session_after_reload(self):
  r=self.c.get('/api/session');self.assertEqual(r.status_code,200)
  csrf=r.json()['csrf_token'];self.assertNotEqual(csrf,self.c.cookies.get('paper_session'))
  r=self.c.post('/api/paper/action',headers={'x-csrf-token':csrf},json={'action':'stop'});self.assertEqual(r.status_code,200)
 def test_096_private_api_not_cached(self):
  for path in ['/api/paper','/api/paper/trades','/api/paper/equity-history','/api/session']:
   r=self.c.get(path,headers=self.headers)
   self.assertEqual(r.status_code,200)
   self.assertEqual(r.headers.get('cache-control'),'no-store')
   self.assertEqual(r.headers.get('pragma'),'no-cache')
  r=self.c.get('/api/paper',cookies={'paper_session':'invalid'})
  self.assertEqual(r.headers.get('cache-control'),'no-store')
 def test_097_risk_lock_liquidates_open_paper_position(self):
  self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'})
  import app
  with app.LOCK:
   with app.connect() as db:
    db.execute('UPDATE state SET cash=20,asset=0.0002,price=76000,running=1,ticks=1,locked=0 WHERE id=1')
    db.execute('INSERT INTO paper_trades(opened,entry,qty,mode) VALUES(?,?,?,?)',('2026-01-01T00:00:00Z',76000,0.0002,'smart'))
    db.commit()
  r=self.c.post('/api/paper/action',headers=self.headers,json={'action':'tick'})
  self.assertEqual(r.status_code,200)
  state=r.json()
  self.assertTrue(state['locked'])
  self.assertFalse(state['running'])
  self.assertEqual(state['asset'],0)
  self.assertIsNone(state['open_trade'])
  self.assertTrue(any(e['action']=='risk_liquidation' for e in self.c.get('/api/paper/events').json()))
 def test_098_mode_allocation_limits(self):
  # Each mode must limit first simulated entry to its configured equity share.
  for mode,cap in [('defensive',.10),('smart',.20),('aggressive',.30)]:
   self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)
   self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'risk_mode','mode':mode}).status_code,200)
   self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'start'}).status_code,200)
   state=self.c.post('/api/paper/action',headers=self.headers,json={'action':'tick'}).json()
   self.assertIsNotNone(state['open_trade'],mode)
   exposure=state['asset']*state['price']
   self.assertLessEqual(exposure,state['equity']*cap+0.001,mode)
   self.assertGreater(exposure,0,mode)
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)
 def test_099_restart_requires_manual_start(self):
  # A persisted running flag must not silently resume the paper worker on restart.
  self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'})
  self.c.post('/api/paper/action',headers=self.headers,json={'action':'start'})
  before=self.c.get('/api/paper',headers=self.headers).json()['ticks']
  with TestClient(self.app.app) as restarted:
   restarted.cookies.update(self.c.cookies)
   state=restarted.get('/api/paper',headers=self.headers).json()
   self.assertFalse(state['running'])
   self.assertEqual(state['ticks'],before)
   self.assertFalse(state['locked'])
   events=restarted.get('/api/paper/events',headers=self.headers).json()
   self.assertTrue(any(e['action']=='restart_pause' for e in events))
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'tick'}).status_code,409)
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'start'}).status_code,200)
  self.c.post('/api/paper/action',headers=self.headers,json={'action':'stop'})
 def test_0995_three_consecutive_losses_lock_engine(self):
  # A third losing close must lock the paper engine, preserving its audit trail.
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)
  import app
  with app.LOCK:
   with app.connect() as db:
    db.execute('UPDATE state SET cash=35.16,asset=0.00009,price=76000,running=1,ticks=11,losses=2,locked=0 WHERE id=1')
    db.execute('UPDATE settings SET peak=42,consecutive_losses=2 WHERE id=1')
    db.execute('INSERT INTO paper_trades(opened,entry,qty,mode) VALUES(?,?,?,?)',('2026-01-01T00:00:00Z',77000,0.00009,'smart'))
    db.commit()
  response=self.c.post('/api/paper/action',headers=self.headers,json={'action':'tick'})
  self.assertEqual(response.status_code,200)
  state=response.json()
  self.assertEqual(state['consecutive_losses'],3)
  self.assertTrue(state['locked'])
  self.assertFalse(state['running'])
  self.assertIsNone(state['open_trade'])
  self.assertEqual(state['asset'],0)
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'start'}).status_code,409)
  trades=self.c.get('/api/paper/trades',headers=self.headers).json()
  self.assertLess(trades[0]['pnl'],0)
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)
 def test_0996_transaction_rollback_preserves_paper_state(self):
  # An exception halfway through a multi-table update must leave no partial audit data.
  import app
  with app.LOCK:
   with app.connect() as db:
    initial=db.execute('SELECT cash,ticks FROM state WHERE id=1').fetchone()
    event_count=db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
   with self.assertRaises(RuntimeError):
    with app.connect() as db:
     db.execute('UPDATE state SET cash=cash-1,ticks=ticks+1 WHERE id=1')
     db.execute('INSERT INTO events(time,action,detail) VALUES(?,?,?)',('test','interrupted','rollback'))
     raise RuntimeError('simulated interrupted operation')
   with app.connect() as db:
    self.assertEqual(db.execute('SELECT cash,ticks FROM state WHERE id=1').fetchone(),initial)
    self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0],event_count)
 def test_0997_paper_ledger_integrity_after_reconnect(self):
  import app
  with app.LOCK:
   with app.connect() as db:
    db.execute('INSERT INTO events(time,action,detail) VALUES(?,?,?)',('test','integrity_probe','durable'))
   with app.connect() as db:
    self.assertEqual(db.execute('PRAGMA quick_check').fetchone()[0],'ok')
    self.assertEqual(db.execute("SELECT COUNT(*) FROM events WHERE action='integrity_probe'").fetchone()[0],1)
 def test_09975_invalid_ledger_fails_closed_without_new_trade(self):
  import app
  with app.LOCK:
   with app.connect() as db:
    db.execute('UPDATE state SET running=1,cash=-1 WHERE id=1')
    ticks=db.execute('SELECT ticks FROM state WHERE id=1').fetchone()[0]
    trades=db.execute('SELECT COUNT(*) FROM paper_trades').fetchone()[0]
  response=self.c.post('/api/paper/action',headers=self.headers,json={'action':'tick'})
  self.assertEqual(response.status_code,409)
  with app.LOCK:
   with app.connect() as db:
    self.assertEqual(db.execute('SELECT ticks FROM state WHERE id=1').fetchone()[0],ticks)
    self.assertEqual(db.execute('SELECT COUNT(*) FROM paper_trades').fetchone()[0],trades)
    db.execute('UPDATE state SET cash=42,running=0 WHERE id=1')
 def test_09976_orphaned_paper_asset_fails_closed(self):
  import app
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)
  with app.LOCK:
   with app.connect() as db:
    db.execute('UPDATE state SET running=1,asset=0.001 WHERE id=1')
    before=db.execute('SELECT ticks FROM state WHERE id=1').fetchone()[0]
  r=self.c.post('/api/paper/action',headers=self.headers,json={'action':'tick'})
  self.assertEqual(r.status_code,409)
  with app.LOCK:
   with app.connect() as db:
    self.assertEqual(db.execute('SELECT ticks FROM state WHERE id=1').fetchone()[0],before)
    self.assertEqual(db.execute('SELECT COUNT(*) FROM paper_trades').fetchone()[0],0)
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)
 def test_0997_browser_permissions_disabled(self):
  for path in ('/','/api/health','/api/status'):
   r=self.c.get(path)
   self.assertEqual(r.status_code,200)
   self.assertEqual(r.headers.get('permissions-policy'),'camera=(), microphone=(), geolocation=()')
 def test_0997_logout_disables_caching(self):
  # Logout responses must never be cached by an intermediary or browser.
  r=self.c.post('/api/logout',headers=self.headers)
  self.assertEqual(r.status_code,200)
  self.assertEqual(r.headers.get('cache-control'),'no-store')
  self.assertIn('paper_session=',r.headers.get('set-cookie',''))
  # Restore the authenticated test client for subsequent tests.
  login=self.c.post('/api/login',json={'password':'unit-test-only'})
  self.assertEqual(login.status_code,200)
  self.__class__.headers={'x-csrf-token':login.json()['csrf_token']}
 def test_0998_api_version_matches_release(self):
  import app
  self.assertEqual(app.app.version,'1.3.42')
 def test_09985_health_reports_current_release(self):
  import app
  r=self.c.get('/api/health')
  self.assertEqual(r.status_code,200)
  self.assertEqual(r.json()['version'],app.app.version)
  self.assertEqual(r.json()['mode'],'paper')
 def test_0999_all_seven_navigation_sections_preserved(self):
  from pathlib import Path
  import app
  html=(Path(app.__file__).parent/'static'/'index.html').read_text(encoding='utf-8')
  self.assertIn("const tabs=['داشبورد','مغز ربات','بازار','معاملات','استراتژی','آزمایشگاه','امنیت']",html)
  self.assertIn("id=\"tabs\"",html)
  self.assertIn('nav.innerHTML',html)
 def test_10_logout(self):
  self.assertEqual(self.c.post('/api/logout',headers=self.headers).status_code,200)
  self.assertEqual(self.c.get('/api/paper').status_code,401)
  self.assertEqual(self.c.get('/api/session').status_code,401)

 def test_09991_corrupt_risk_counters_fail_closed(self):
  import app
  for bad_update in ["UPDATE settings SET consecutive_losses=2 WHERE id=1", "UPDATE settings SET risk_mode='unknown' WHERE id=1"]:
   self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)
   self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'start'}).status_code,200)
   with app.LOCK:
    with app.connect() as db: db.execute(bad_update)
   before=self.c.get('/api/paper').json()['ticks']
   response=self.c.post('/api/paper/action',headers=self.headers,json={'action':'tick'})
   self.assertEqual(response.status_code,409)
   self.assertEqual(self.c.get('/api/paper').json()['ticks'],before)
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)

 def test_09992_start_rejects_corrupt_position_without_mutation(self):
  import app
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)
  with app.LOCK:
   with app.connect() as db:
    db.execute('UPDATE state SET asset=0.002 WHERE id=1')
    events_before=db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
  r=self.c.post('/api/paper/action',headers=self.headers,json={'action':'start'})
  self.assertEqual(r.status_code,409)
  with app.LOCK:
   with app.connect() as db:
    self.assertEqual(db.execute('SELECT running FROM state WHERE id=1').fetchone()[0],0)
    self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0],events_before)
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)

 def test_09993_risk_mode_rejects_corrupt_ledger_without_mutation(self):
  import app
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)
  with app.LOCK:
   with app.connect() as db:
    db.execute('UPDATE state SET asset=0.005 WHERE id=1')
    events_before=db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
  r=self.c.post('/api/paper/action',headers=self.headers,json={'action':'risk_mode','mode':'aggressive'})
  self.assertEqual(r.status_code,409)
  with app.LOCK:
   with app.connect() as db:
    self.assertEqual(db.execute('SELECT risk_mode FROM settings WHERE id=1').fetchone()[0],'smart')
    self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0],events_before)
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)

 def test_09994_invalid_peak_or_flags_block_start_without_mutation(self):
  import app
  for corruption in ["UPDATE settings SET peak=1 WHERE id=1", "UPDATE state SET locked=2 WHERE id=1", "UPDATE state SET running=2 WHERE id=1"]:
   self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)
   with app.LOCK:
    with app.connect() as db:
     db.execute(corruption)
     events_before=db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
   response=self.c.post('/api/paper/action',headers=self.headers,json={'action':'start'})
   self.assertEqual(response.status_code,409,corruption)
   with app.LOCK:
    with app.connect() as db:
     self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0],events_before)
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)

 def test_09995_duplicate_open_positions_fail_closed(self):
  import app
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)
  with app.LOCK:
   with app.connect() as db:
    db.execute('UPDATE state SET asset=0.0004 WHERE id=1')
    for _ in range(2):
     db.execute('INSERT INTO paper_trades(opened,entry,qty,mode) VALUES(?,?,?,?)',('2026-01-01T00:00:00Z',76000,0.0002,'smart'))
    before=db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
    db.commit()
  response=self.c.post('/api/paper/action',headers=self.headers,json={'action':'start'})
  self.assertEqual(response.status_code,409)
  with app.LOCK:
   with app.connect() as db:
    self.assertEqual(db.execute('SELECT running FROM state WHERE id=1').fetchone()[0],0)
    self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0],before)
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)

 def test_09997_invalid_open_position_mode_blocks_start(self):
  import app
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)
  with app.LOCK:
   with app.connect() as db:
    db.execute('UPDATE state SET cash=40,asset=0.00002 WHERE id=1')
    db.execute('INSERT INTO paper_trades(opened,entry,qty,mode) VALUES(?,?,?,?)',('2026-01-01T00:00:00Z',76000,0.00002,'unknown'))
    before=db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
  response=self.c.post('/api/paper/action',headers=self.headers,json={'action':'start'})
  self.assertEqual(response.status_code,409)
  with app.LOCK:
   with app.connect() as db:
    self.assertEqual(db.execute('SELECT running FROM state WHERE id=1').fetchone()[0],0)
    self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0],before)
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)

 def test_09994_readiness_is_not_cached(self):
  response=self.c.get('/api/ready')
  self.assertEqual(response.status_code,200)
  self.assertEqual(response.headers.get('cache-control'),'no-store')

 def test_09995_deployment_readiness_paper_only(self):
  response=self.c.get('/api/ready')
  self.assertEqual(response.status_code,200)
  self.assertEqual(response.json(),{'ready':True,'mode':'paper','live_trading':False})
  import app
  from unittest.mock import patch
  with patch.object(app,'SECRET','short'):
   response=self.c.get('/api/ready')
   self.assertEqual(response.status_code,503)
   self.assertNotIn('short',response.text)

 def test_099951_readiness_handles_storage_failure_without_details(self):
  import app
  from unittest.mock import patch
  with patch.object(app,'connect',side_effect=OSError('private filesystem path')):
   response=self.c.get('/api/ready')
  self.assertEqual(response.status_code,503)
  self.assertEqual(response.json()['detail'],'Paper ledger unavailable')
  self.assertNotIn('private filesystem path',response.text)

 def test_099952_readiness_rejects_invalid_paper_state(self):
  import app
  with app.LOCK:
   with app.connect() as db:
    db.execute('UPDATE state SET price=0 WHERE id=1')
  response=self.c.get('/api/ready')
  self.assertEqual(response.status_code,503)
  self.assertEqual(response.json()['detail'],'Paper ledger state invalid')
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)

 def test_099953_readiness_rejects_invalid_risk_settings(self):
  import app
  with app.LOCK:
   with app.connect() as db:
    original=db.execute('SELECT risk_mode,peak,consecutive_losses FROM settings WHERE id=1').fetchone()
    db.execute('UPDATE settings SET risk_mode=? WHERE id=1',('invalid',))
  try:
   response=self.c.get('/api/ready')
   self.assertEqual(response.status_code,503)
   self.assertEqual(response.json()['detail'],'Paper risk settings invalid')
  finally:
   with app.LOCK:
    with app.connect() as db:
     db.execute('UPDATE settings SET risk_mode=?,peak=?,consecutive_losses=? WHERE id=1',original)

 def test_0999535_readiness_rejects_orphaned_paper_asset(self):
  import app
  with app.LOCK:
   with app.connect() as db:
    previous=db.execute('SELECT cash,asset FROM state WHERE id=1').fetchone()
    db.execute('UPDATE state SET cash=?,asset=? WHERE id=1',(0,0.00001))
  try:
   response=self.c.get('/api/ready')
   self.assertEqual(response.status_code,503)
   self.assertEqual(response.json()['detail'],'Paper position state invalid')
  finally:
   with app.LOCK:
    with app.connect() as db:
     db.execute('UPDATE state SET cash=?,asset=? WHERE id=1',previous)

 def test_099954_health_is_not_cached(self):
  response=self.c.get('/api/health')
  self.assertEqual(response.status_code,200)
  self.assertEqual(response.headers.get('cache-control'),'no-store')
  self.assertEqual(response.json()['mode'],'paper')
  self.assertFalse(response.json()['live_trading'])

 def test_099955_security_headers_on_ui_and_api(self):
  for path in ('/', '/api/health', '/api/status'):
   response=self.c.get(path)
   self.assertEqual(response.status_code,200)
   self.assertEqual(response.headers.get('x-content-type-options'),'nosniff')
   self.assertEqual(response.headers.get('referrer-policy'),'no-referrer')

 def test_099956_clickjacking_header_on_ui_api_and_errors(self):
  for path, expected in (('/',200),('/api/health',200),('/api/ready',200),('/missing-route',404)):
   response=self.c.get(path)
   self.assertEqual(response.status_code,expected)
   self.assertEqual(response.headers.get('x-frame-options'),'DENY')

 def test_099957_duplicate_action_keys_rejected_without_mutation(self):
  import app
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)
  with app.LOCK:
   with app.connect() as db:
    before=db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
  response=self.c.post('/api/paper/action',headers={**self.headers,'content-type':'application/json'},content=b'{"action":"start","action":"stop"}')
  self.assertEqual(response.status_code,400)
  with app.LOCK:
   with app.connect() as db:
    self.assertEqual(db.execute('SELECT running FROM state WHERE id=1').fetchone()[0],0)
    self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0],before)

 def test_099958_nonfinite_json_rejected_without_mutation(self):
  import app
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)
  for payload in (b'{"action":"start","extra":NaN}',b'{"action":"start","extra":Infinity}',b'{"action":"start","extra":-Infinity}'):
   response=self.c.post('/api/paper/action',headers={**self.headers,'content-type':'application/json'},content=payload)
   self.assertEqual(response.status_code,400)
   with app.LOCK:
    with app.connect() as db:
     self.assertEqual(db.execute('SELECT running FROM state WHERE id=1').fetchone()[0],0)
  for payload in (b'{"password":"unit-test-only","extra":NaN}',b'{"password":"unit-test-only","extra":Infinity}'):
   response=self.c.post('/api/login',headers={'content-type':'application/json'},content=payload)
   self.assertEqual(response.status_code,400)
   self.assertNotIn('set-cookie',response.headers)

 def test_099959_service_worker_never_caches_dashboard(self):
  from pathlib import Path
  import app
  sw=(Path(app.__file__).parent/'static'/'service-worker.js').read_text()
  self.assertNotIn("addAll(['/','/manifest.webmanifest'])",sw)
  self.assertIn("url.pathname==='/'",sw)
  self.assertIn("url.pathname.startsWith('/api/')",sw)
  self.assertIn("caches.delete(k)",sw)

 def test_09995_session_evicted_after_auth_returns_401(self):
  from unittest.mock import patch
  import app
  removed={}
  def evict(request):
   token=request.cookies.get('paper_session','')
   with app.LOCK:
    removed[token]=app.CSRF_TOKENS.pop(token,None)
  try:
   with patch.object(app,'auth',side_effect=evict):
    r=self.c.get('/api/session')
   self.assertEqual(r.status_code,401)
  finally:
   with app.LOCK:
    for token,csrf in removed.items():
     if csrf is not None:app.CSRF_TOKENS[token]=csrf

 def test_099955_csrf_evicted_between_reads_returns_403(self):
  import app
  from unittest.mock import patch
  class EvictingDict(dict):
   def __getitem__(self,key):
    raise AssertionError('CSRF secret must not be read twice')
  with app.LOCK:
   old=app.CSRF_TOKENS
   app.CSRF_TOKENS=EvictingDict(old)
  try:
   r=self.c.post('/api/paper/action',headers={'x-csrf-token':'incorrect'},json={'action':'tick'})
   self.assertEqual(r.status_code,403)
  finally:
   with app.LOCK:app.CSRF_TOKENS=old

 def test_09996_mobile_ui_seven_tabs_smoke(self):
  import re
  page=self.c.get('/')
  self.assertEqual(page.status_code,200)
  html=page.text
  self.assertIn('width=device-width',html)
  self.assertIn('safe-area-inset-bottom',html)
  self.assertIn('id="tabs"',html)
  match=re.search(r'const tabs\s*=\s*\[(.*?)\]',html,re.S)
  self.assertIsNotNone(match,'Navigation tab declaration missing')
  tabs=re.findall(r"['\"]([^'\"]+)['\"]",match.group(1))
  self.assertEqual(len(tabs),7)
  self.assertEqual(len(set(tabs)),7)
  self.assertEqual(self.c.get('/api/health').json()['version'],'1.3.42')

 def test_09997_action_rejects_non_json_without_mutation(self):
  before=self.c.get('/api/paper').json()
  response=self.c.post('/api/paper/action',headers={**self.headers,'content-type':'text/plain'},content='{"action":"reset"}')
  self.assertEqual(response.status_code,415)
  self.assertEqual(self.c.get('/api/paper').json(),before)

 def test_09998_simulated_price_underflow_does_not_write(self):
  import app
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)
  with app.LOCK:
   with app.connect() as db:
    db.execute('UPDATE state SET price=0.00001,running=1,ticks=1 WHERE id=1')
    before=db.execute('SELECT COUNT(*) FROM equity_history').fetchone()[0]
  response=self.c.post('/api/paper/action',headers=self.headers,json={'action':'tick'})
  self.assertEqual(response.status_code,409)
  with app.LOCK:
   with app.connect() as db:
    self.assertEqual(db.execute('SELECT ticks FROM state WHERE id=1').fetchone()[0],1)
    self.assertEqual(db.execute('SELECT COUNT(*) FROM equity_history').fetchone()[0],before)
  self.assertEqual(self.c.post('/api/paper/action',headers=self.headers,json={'action':'reset'}).status_code,200)

if __name__=='__main__':unittest.main()

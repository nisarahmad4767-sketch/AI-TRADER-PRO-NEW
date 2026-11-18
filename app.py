"""AI TRADER PRO — paper-only backend. No live market requests or real orders."""
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from datetime import datetime, timezone
import os, sqlite3, secrets, hashlib, hmac, json, threading, time, math
from urllib.parse import urlparse
from contextlib import contextmanager, asynccontextmanager

BASE=Path(__file__).parent
DB=Path(os.environ.get('DB_PATH',str(BASE/'paper.sqlite3')))
PASSWORD=os.environ.get('APP_PASSWORD','')
SECRET=os.environ.get('SESSION_SECRET','')
LOCK=threading.RLock()
@asynccontextmanager
async def lifespan(app):
    # Fail closed after a process restart: require an explicit new start command.
    with LOCK:
        with connect() as db:
            changed=db.execute('UPDATE state SET running=0 WHERE id=1 AND running=1').rowcount
            if changed:
                db.execute('INSERT INTO events(time,action,detail) VALUES(?,?,?)',
                           (datetime.now(timezone.utc).isoformat(),'restart_pause',
                            'paper engine paused after process startup; manual start required'))
    STOP_WORKER.clear()
    if AUTO_ENABLED:
        threading.Thread(target=paper_worker,daemon=True,name='paper-worker').start()
    yield
    STOP_WORKER.set()

app=FastAPI(title='AI TRADER PRO',version='1.3.42',lifespan=lifespan)
SESSIONS={}
CSRF_TOKENS={}
LOGIN_FAILURES={}
AUTO_INTERVAL=max(2,int(os.environ.get('PAPER_TICK_SECONDS','15')))
AUTO_ENABLED=os.environ.get('PAPER_AUTO_WORKER','0')=='1'
STOP_WORKER=threading.Event()
app.mount('/static',StaticFiles(directory=BASE/'static'),name='static')

@app.middleware('http')
async def no_store_api_responses(request:Request,call_next):
    response=await call_next(request)
    # Safe response headers for both API and mobile UI, without changing routes.
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='no-referrer'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'
    if request.url.path.startswith('/api/'):
        response.headers['Cache-Control']='no-store'
        response.headers['Pragma']='no-cache'
    return response


def _connect():
    DB.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(DB,timeout=10)
    # Favor durable commits over speed for the paper-trading audit trail.
    db.execute('PRAGMA synchronous=FULL')
    # Reject a damaged paper ledger rather than silently trading on invalid state.
    if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
        db.close()
        raise sqlite3.DatabaseError('Paper ledger integrity check failed')
    db.execute('CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), cash REAL NOT NULL, asset REAL NOT NULL, price REAL NOT NULL, running INTEGER NOT NULL, ticks INTEGER NOT NULL, losses INTEGER NOT NULL, locked INTEGER NOT NULL)')
    db.execute('INSERT OR IGNORE INTO state VALUES(1,42,0,76000,0,0,0,0)')
    db.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS paper_trades (id INTEGER PRIMARY KEY AUTOINCREMENT, opened TEXT NOT NULL, closed TEXT, entry REAL NOT NULL, exit REAL, qty REAL NOT NULL, pnl REAL, mode TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS equity_history (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, equity REAL NOT NULL, price REAL NOT NULL, ticks INTEGER NOT NULL)')
    db.execute('INSERT INTO equity_history(time,equity,price,ticks) SELECT ?,42,76000,0 WHERE NOT EXISTS(SELECT 1 FROM equity_history)',(datetime.now(timezone.utc).isoformat(),))
    db.execute('CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK(id=1), risk_mode TEXT NOT NULL, peak REAL NOT NULL, consecutive_losses INTEGER NOT NULL)')
    db.execute("INSERT OR IGNORE INTO settings VALUES(1,'smart',42,0)")
    db.commit();return db

@contextmanager
def connect():
    db=_connect()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def auth(request:Request):
    if not PASSWORD or len(SECRET)<32:
        raise HTTPException(503,'Configure APP_PASSWORD and SESSION_SECRET before deployment')
    token=request.cookies.get('paper_session','')
    with LOCK:
        expiry=SESSIONS.get(token)
        if not expiry or expiry<=time.time():
            SESSIONS.pop(token,None)
            CSRF_TOKENS.pop(token,None)
            raise HTTPException(401,'Authentication required')
    if request.method not in ('GET','HEAD','OPTIONS'):
        origin=request.headers.get('origin','')
        if origin:
            parsed=urlparse(origin)
            if parsed.netloc!=request.headers.get('host') or parsed.scheme not in ('http','https'):
                raise HTTPException(403,'Origin rejected')
        # Read the CSRF secret once while holding the lock. A concurrent
        # session eviction must not cause a KeyError / HTTP 500.
        with LOCK:
            csrf_secret=CSRF_TOKENS.get(token)
        if not csrf_secret or not hmac.compare_digest(request.headers.get('x-csrf-token',''),csrf_secret):
            raise HTTPException(403,'CSRF token required')

def validate_paper_ledger(db, s):
    # Fail closed on inconsistent persisted balances instead of simulating orders.
    if (not all(math.isfinite(v) for v in (s['cash'],s['asset'],s['price'],s['peak']))
            or s['cash'] < 0 or s['asset'] < 0 or s['price'] <= 0 or s['peak'] <= 0):
        raise HTTPException(409,'Invalid paper ledger state; manual review required')
    # Stored control flags and peak equity must remain internally consistent.
    equity=s['cash']+s['asset']*s['price']
    raw_running,raw_locked=db.execute('SELECT running,locked FROM state WHERE id=1').fetchone()
    if (not math.isfinite(equity) or raw_running not in (0,1)
            or raw_locked not in (0,1)
            or s['peak'] + max(1e-8,abs(equity)*1e-10) < equity):
        raise HTTPException(409,'Inconsistent paper engine controls or equity peak; manual review required')
    # Reject inconsistent risk counters and unsupported modes before changing the ledger.
    if (s['risk_mode'] not in ('defensive','smart','aggressive')
            or not isinstance(s['ticks'],int) or s['ticks'] < 0
            or not isinstance(s['losses'],int) or s['losses'] < 0
            or not isinstance(s['consecutive_losses'],int)
            or s['consecutive_losses'] != s['losses']):
        raise HTTPException(409,'Inconsistent paper risk settings; manual review required')
    # A corrupt or duplicated open position must never generate a simulated order.
    open_positions=db.execute('SELECT entry,qty,mode FROM paper_trades WHERE closed IS NULL').fetchall()
    if len(open_positions)>1 or (open_positions and (
            not all(math.isfinite(v) and v>0 for v in open_positions[0][:2])
            or open_positions[0][2] not in ('defensive','smart','aggressive')
            or not math.isclose(db.execute('SELECT asset FROM state WHERE id=1').fetchone()[0],open_positions[0][1],rel_tol=1e-8,abs_tol=1e-10)
        )) or (not open_positions and not math.isclose(s['asset'],0,abs_tol=1e-10)):
        raise HTTPException(409,'Inconsistent paper position; manual review required')

def paper_tick(db):
    s=snapshot(db)
    # Calculations must use persisted precision, not rounded API display values.
    s['cash'],s['asset'],s['price']=db.execute('SELECT cash,asset,price FROM state WHERE id=1').fetchone()
    if not s['running'] or s['locked']:raise HTTPException(409,'Paper engine stopped or locked')
    validate_paper_ledger(db,s)
    changes=[.001,-.002,.0005,-.0015,.002,-.003,.001,.003,-.001,.0025,-.004,.0007]
    delta=changes[s['ticks']%len(changes)]
    price=round(s['price']*(1+delta),4)
    if not math.isfinite(price) or price <= 0:
        raise HTTPException(409,'Simulated price underflow; manual review required')
    equity=s['cash']+s['asset']*price
    mode=s['risk_mode']
    allocation={'defensive':.10,'smart':.20,'aggressive':.30}[mode]
    stop_pct=.008
    allocation=min(allocation,.005/stop_pct)
    position=db.execute('SELECT id,entry,qty FROM paper_trades WHERE closed IS NULL ORDER BY id DESC LIMIT 1').fetchone()
    cash=s['cash'];asset=s['asset'];losses=s['consecutive_losses']
    if position:
        trade_id,entry,qty=position
        if price<=entry*(1-stop_pct) or price>=entry*1.014 or (s['ticks']%12==11):
            proceeds=qty*price
            pnl=(price-entry)*qty
            cash+=proceeds;asset=max(0,asset-qty)
            losses=losses+1 if pnl<0 else 0
            db.execute('UPDATE paper_trades SET closed=?,exit=?,pnl=? WHERE id=?',(datetime.now(timezone.utc).isoformat(),price,pnl,trade_id))
    elif s['ticks']%3==0 and delta>=0 and losses<3:
        cost=min(cash,equity*allocation)
        if cost>0:
            qty=cost/price
            cash-=cost;asset+=qty
            db.execute('INSERT INTO paper_trades(opened,entry,qty,mode) VALUES(?,?,?,?)',(datetime.now(timezone.utc).isoformat(),price,qty,mode))
    equity=cash+asset*price
    peak=max(s['peak'],equity)
    locked=equity<=41.58 or (peak>0 and (peak-equity)/peak>=.01) or losses>=3
    # Emergency paper-only liquidation: a locked engine must not retain exposure.
    if locked and asset>0:
        open_position=db.execute('SELECT id,entry,qty FROM paper_trades WHERE closed IS NULL ORDER BY id DESC LIMIT 1').fetchone()
        if open_position:
            trade_id,entry,qty=open_position
            db.execute('UPDATE paper_trades SET closed=?,exit=?,pnl=? WHERE id=?',(datetime.now(timezone.utc).isoformat(),price,(price-entry)*qty,trade_id))
        cash+=asset*price
        asset=0.0
        equity=cash
        db.execute('INSERT INTO events(time,action,detail) VALUES(?,?,?)',(datetime.now(timezone.utc).isoformat(),'risk_liquidation','emergency paper-only liquidation'))
    db.execute('UPDATE state SET cash=?,asset=?,price=?,ticks=ticks+1,losses=?,locked=?,running=? WHERE id=1',(cash,asset,price,losses,int(locked),0 if locked else 1))
    db.execute('UPDATE settings SET peak=?,consecutive_losses=? WHERE id=1',(peak,losses))
    db.execute('INSERT INTO equity_history(time,equity,price,ticks) VALUES(?,?,?,?)',(datetime.now(timezone.utc).isoformat(),equity,price,s['ticks']+1))

def paper_worker():
    while not STOP_WORKER.wait(AUTO_INTERVAL):
        try:
            with LOCK:
                with connect() as db:
                    s=snapshot(db)
                    if s['running'] and not s['locked']:
                        paper_tick(db)
                        db.execute('INSERT INTO events(time,action,detail) VALUES(?,?,?)',(datetime.now(timezone.utc).isoformat(),'auto_tick','synthetic paper only'))
        except Exception:
            import logging
            logging.exception('Paper simulation worker error')

def snapshot(db):
    cash,asset,price,running,ticks,losses,locked=db.execute('SELECT cash,asset,price,running,ticks,losses,locked FROM state WHERE id=1').fetchone()
    risk_mode,peak,consecutive_losses=db.execute('SELECT risk_mode,peak,consecutive_losses FROM settings WHERE id=1').fetchone()
    closed=db.execute('SELECT COUNT(*),COALESCE(SUM(pnl),0),COALESCE(SUM(CASE WHEN pnl>0 THEN 1 ELSE 0 END),0) FROM paper_trades WHERE closed IS NOT NULL').fetchone()
    open_trade=db.execute('SELECT id,entry,qty FROM paper_trades WHERE closed IS NULL ORDER BY id DESC LIMIT 1').fetchone()
    return dict(risk_mode=risk_mode,closed_trades=closed[0],realized_pnl=round(closed[1],4),wins=closed[2],peak=peak,drawdown_pct=round(max(0,(peak-(cash+asset*price))/peak)*100,3) if peak else 0,consecutive_losses=consecutive_losses,open_trade=dict(id=open_trade[0],entry=open_trade[1],qty=open_trade[2]) if open_trade else None,cash=round(cash,4),asset=round(asset,8),price=price,equity=round(cash+asset*price,4),running=bool(running),ticks=ticks,losses=losses,locked=bool(locked),mode='paper',market_source='simulation',live_trading_enabled=False,binance_connected=False)

@app.get('/')
def home():return FileResponse(BASE/'static'/'index.html')
@app.get('/manifest.webmanifest')
def manifest():return FileResponse(BASE/'static'/'manifest.webmanifest',media_type='application/manifest+json')
@app.get('/service-worker.js')
def worker():return FileResponse(BASE/'static'/'service-worker.js',media_type='application/javascript')
@app.get('/api/health')
def health(response:Response):
    response.headers['Cache-Control']='no-store'
    return {'ok':True,'version':app.version,'mode':'paper','live_trading':False,'time':datetime.now(timezone.utc).isoformat()}
@app.get('/api/ready')
def ready(response:Response):
    response.headers['Cache-Control']='no-store'
    # Deployment readiness without exposing passwords or private configuration.
    if not PASSWORD or len(SECRET)<32:
        raise HTTPException(503,'Authentication configuration incomplete')
    try:
        with LOCK:
            with connect() as db:
                row=db.execute('SELECT cash,asset,price,running,ticks,losses,locked FROM state WHERE id=1').fetchone()
                if row is None:
                    raise HTTPException(503,'Paper ledger not initialized')
                cash,asset,price,running,ticks,losses,locked=row
                if (not all(math.isfinite(v) for v in (cash,asset,price))
                    or cash<0 or asset<0 or price<=0 or ticks<0 or losses<0
                    or running not in (0,1) or locked not in (0,1)):
                    raise HTTPException(503,'Paper ledger state invalid')
                settings=db.execute('SELECT risk_mode,peak,consecutive_losses FROM settings WHERE id=1').fetchone()
                if (settings is None or settings[0] not in ('defensive','smart','aggressive')
                    or not math.isfinite(settings[1]) or settings[1]<=0
                    or settings[2]<0 or settings[1]+max(1e-8,(cash+asset*price)*1e-10)<cash+asset*price):
                    raise HTTPException(503,'Paper risk settings invalid')
                # Readiness must reject an orphaned simulated position before serving traffic.
                positions=db.execute('SELECT qty FROM paper_trades WHERE closed IS NULL').fetchall()
                if (len(positions)>1 or (positions and (not math.isfinite(positions[0][0])
                    or positions[0][0]<=0 or not math.isclose(asset,positions[0][0],rel_tol=1e-8,abs_tol=1e-10)))
                    or (not positions and not math.isclose(asset,0,abs_tol=1e-10))):
                    raise HTTPException(503,'Paper position state invalid')
    except (sqlite3.Error, OSError):
        raise HTTPException(503,'Paper ledger unavailable')
    return {'ready':True,'mode':'paper','live_trading':False}

@app.get('/api/status')
def status():return {'market_source':'simulation','binance_connected':False,'live_trading_enabled':False,'paper_starting_balance_usd':42,'notice':'No real prices or orders are requested.'}
@app.post('/api/login')
async def login(request:Request):
    if not PASSWORD or len(SECRET)<32:raise HTTPException(503,'Server authentication not configured')
    ip=request.client.host if request.client else 'unknown'
    now=time.time()
    with LOCK:
        attempts=[t for t in LOGIN_FAILURES.get(ip,[]) if now-t<300]
        LOGIN_FAILURES[ip]=attempts
        if len(attempts)>=5:raise HTTPException(429,'Too many login attempts. Retry later.')
    # Reject unexpected media types before parsing credentials.
    media_type=request.headers.get('content-type','').split(';',1)[0].strip().lower()
    if media_type!='application/json':
        with LOCK:LOGIN_FAILURES.setdefault(ip,[]).append(now)
        raise HTTPException(415,'Login requires application/json')
    # Bound unauthenticated login payloads to avoid excessive JSON parsing.
    # Read at most 4097 bytes; request.body() would buffer an arbitrarily large payload.
    chunks=[]
    total=0
    async for chunk in request.stream():
        total+=len(chunk)
        if total>4096:
            with LOCK:LOGIN_FAILURES.setdefault(ip,[]).append(now)
            raise HTTPException(413,'Login payload too large')
        chunks.append(chunk)
    body=b''.join(chunks)
    try:
        data=json.loads(body,object_pairs_hook=reject_duplicate_json_keys,parse_constant=reject_nonfinite_json_constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        # Malformed login requests count toward the same per-IP throttle.
        with LOCK:LOGIN_FAILURES.setdefault(ip,[]).append(now)
        raise HTTPException(400,'Invalid login JSON')
    if not isinstance(data,dict):
        with LOCK:LOGIN_FAILURES.setdefault(ip,[]).append(now)
        raise HTTPException(400,'Login JSON must be an object')
    # Passwords must be JSON strings; never coerce arrays, numbers or null to text.
    if not isinstance(data.get('password'),str):
        with LOCK:LOGIN_FAILURES.setdefault(ip,[]).append(now)
        raise HTTPException(400,'Login password must be a string')
    if not hmac.compare_digest(data.get('password',''),PASSWORD):
        with LOCK:LOGIN_FAILURES.setdefault(ip,[]).append(now)
        raise HTTPException(401,'Invalid password')
    token=secrets.token_urlsafe(32)
    with LOCK:
        LOGIN_FAILURES.pop(ip,None)
        # Prune expired sessions and their CSRF tokens on successful login.
        for old_token, expiry in list(SESSIONS.items()):
            if expiry <= now:
                SESSIONS.pop(old_token,None)
                CSRF_TOKENS.pop(old_token,None)
        # Bound active sessions so repeated logins cannot grow server memory indefinitely.
        # Evict the earliest-expiring session and its CSRF secret as one pair.
        if len(SESSIONS)>=32:
            oldest=min(SESSIONS,key=SESSIONS.get)
            SESSIONS.pop(oldest,None)
            CSRF_TOKENS.pop(oldest,None)
        SESSIONS[token]=now+8*3600
        CSRF_TOKENS[token]=secrets.token_urlsafe(32)
        csrf_token=CSRF_TOKENS[token]
    # Capture the token while locked: another login may evict this session.
    result=JSONResponse({'csrf_token':csrf_token,'expires_in_seconds':28800})
    result.set_cookie('paper_session',token,max_age=28800,httponly=True,secure=request.url.scheme=='https',samesite='strict',path='/')
    result.headers['Cache-Control']='no-store'
    return result

@app.get('/api/session')
def session(request:Request):
    auth(request)
    # A concurrent login may evict this session after auth() returns.
    # Return 401 rather than exposing an unhandled KeyError / HTTP 500.
    with LOCK:
        csrf=CSRF_TOKENS.get(request.cookies.get('paper_session',''))
    if not csrf:
        raise HTTPException(401,'Authentication required')
    result=JSONResponse({'csrf_token':csrf})
    result.headers['Cache-Control']='no-store'
    return result

@app.post('/api/logout')
def logout(request:Request):
    auth(request)
    token=request.cookies.get('paper_session','')
    with LOCK:
        SESSIONS.pop(token,None)
        CSRF_TOKENS.pop(token,None)
    result=JSONResponse({'ok':True})
    result.delete_cookie('paper_session',path='/')
    result.headers['Cache-Control']='no-store'
    return result

@app.get('/api/paper')
def paper(request:Request):
    auth(request)
    with LOCK:
        with connect() as db:return snapshot(db)
def reject_nonfinite_json_constant(value):
    raise ValueError('Non-finite JSON constant not permitted')

def reject_duplicate_json_keys(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key]=value
    return result

@app.post('/api/paper/action')
async def action(request:Request):
    auth(request)
    media_type=request.headers.get('content-type','').split(';',1)[0].strip().lower()
    if media_type!='application/json':
        raise HTTPException(415,'Action requires application/json')
    raw=await request.body()
    if len(raw)>4096:
        raise HTTPException(413,'Action payload too large')
    try:
        body=json.loads(raw,object_pairs_hook=reject_duplicate_json_keys,parse_constant=reject_nonfinite_json_constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise HTTPException(400,'Invalid action JSON')
    cmd=body.get('action') if isinstance(body,dict) else None
    if cmd not in ('start','stop','reset','tick','risk_mode'):raise HTTPException(400,'Invalid action')
    with LOCK:
        with connect() as db:
            s=snapshot(db)
            if cmd=='reset':
                db.execute('UPDATE state SET cash=42,asset=0,price=76000,running=0,ticks=0,losses=0,locked=0 WHERE id=1')
                db.execute('DELETE FROM paper_trades')
                db.execute('DELETE FROM equity_history')
                db.execute('INSERT INTO equity_history(time,equity,price,ticks) VALUES(?,?,?,?)',(datetime.now(timezone.utc).isoformat(),42,76000,0))
                db.execute("UPDATE settings SET risk_mode='smart',peak=42,consecutive_losses=0 WHERE id=1")
            elif cmd=='risk_mode':
                mode=body.get('mode')
                if mode not in ('defensive','smart','aggressive'):raise HTTPException(400,'Invalid risk mode')
                if s['running']:raise HTTPException(409,'Stop engine before changing risk mode')
                # Never alter risk settings on an inconsistent persisted ledger.
                s['cash'],s['asset'],s['price']=db.execute('SELECT cash,asset,price FROM state WHERE id=1').fetchone()
                validate_paper_ledger(db,s)
                db.execute('UPDATE settings SET risk_mode=? WHERE id=1',(mode,))
            elif cmd=='start':
                if s['locked']:raise HTTPException(409,'Risk lock engaged')
                # Reject corrupt persisted positions before enabling the engine.
                s['cash'],s['asset'],s['price']=db.execute('SELECT cash,asset,price FROM state WHERE id=1').fetchone()
                validate_paper_ledger(db,s)
                db.execute('UPDATE state SET running=1 WHERE id=1')
            elif cmd=='stop':db.execute('UPDATE state SET running=0 WHERE id=1')
            elif cmd=='tick':
                if not s['running'] or s['locked']:raise HTTPException(409,'Paper engine stopped or locked')
                paper_tick(db)
            db.execute('INSERT INTO events(time,action,detail) VALUES(?,?,?)',(datetime.now(timezone.utc).isoformat(),cmd,'paper only'))
            db.commit();return snapshot(db)
@app.get('/api/paper/events')
def events(request:Request):
    auth(request)
    with connect() as db:
        return [{'time':t,'action':a,'detail':d} for t,a,d in db.execute('SELECT time,action,detail FROM events ORDER BY id DESC LIMIT 50')]

@app.get('/api/paper/trades')
def trades(request:Request):
    auth(request)
    with connect() as db:
        return [dict(id=i,opened=o,closed=c,entry=e,exit=x,qty=q,pnl=p,mode=m) for i,o,c,e,x,q,p,m in db.execute('SELECT id,opened,closed,entry,exit,qty,pnl,mode FROM paper_trades ORDER BY id DESC LIMIT 100')]

@app.get('/api/paper/equity-history')
def equity_history(request:Request):
    auth(request)
    with LOCK:
        with connect() as db:
            return [{'time':t,'equity':round(e,5),'price':p,'ticks':k} for t,e,p,k in db.execute('SELECT time,equity,price,ticks FROM equity_history ORDER BY id DESC LIMIT 150').fetchall()[::-1]]

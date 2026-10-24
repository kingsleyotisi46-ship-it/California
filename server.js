'use strict';
const crypto = require('node:crypto');
const path = require('node:path');
const express = require('express');
const session = require('express-session');
const connectPgSimple = require('connect-pg-simple');
const { Pool } = require('pg');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const argon2 = require('argon2');
const { z } = require('zod');

const app = express();
const production = process.env.NODE_ENV === 'production';
const port = Number(process.env.PORT || 3000);
const appOrigin = process.env.APP_ORIGIN;
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET must be at least 32 characters');
if (production && (!appOrigin || !/^https:\/\//.test(appOrigin))) throw new Error('APP_ORIGIN must be the production HTTPS origin');

const databaseUrl = new URL(process.env.DATABASE_URL);
const localDatabase = ['localhost','127.0.0.1','::1'].includes(databaseUrl.hostname);
if (!localDatabase) databaseUrl.searchParams.set('sslmode', 'verify-full');
const pool = new Pool({ connectionString: databaseUrl.toString(),
  ssl: localDatabase ? false : { rejectUnauthorized: true },
  max: 10, idleTimeoutMillis: 30000, connectionTimeoutMillis: 5000, application_name: 'california-bank-api' });
pool.on('error', e => console.error('Unexpected idle database error:', e.message));
app.disable('x-powered-by');
app.set('trust proxy', production ? 1 : false);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc:["'self'"], scriptSrc:["'self'"], styleSrc:["'self'"], imgSrc:["'self'","data:"],
  connectSrc:["'self'"], objectSrc:["'none'"], baseUri:["'self'"], frameAncestors:["'none'"],
  formAction:["'self'"], upgradeInsecureRequests: production ? [] : null
}}, crossOriginEmbedderPolicy:false }));
app.use('/api/webhooks/unit', express.raw({ type:['application/json','application/vnd.api+json'], limit:'1mb' }));
app.use(express.json({ limit:'32kb', strict:true }));
app.use((req,res,next) => {
  req.requestId = crypto.randomUUID(); res.setHeader('X-Request-Id',req.requestId);
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.path.startsWith('/api/')) {
    const origin = req.get('origin');
    if (origin && origin !== appOrigin && !( !production && origin === 'http://localhost:3000')) {
      return res.status(403).json({error:'ORIGIN_NOT_ALLOWED',requestId:req.requestId});
    }
  }
  next();
});
const PgSession = connectPgSimple(session);
app.use(session({ store:new PgSession({pool,tableName:'user_sessions',createTableIfMissing:true,pruneSessionInterval:15*60}),
  name:production?'__Host-california.sid':'california.sid', secret:process.env.SESSION_SECRET,
  resave:false,saveUninitialized:false,rolling:true,cookie:{httpOnly:true,secure:production,sameSite:'lax',path:'/',maxAge:30*60*1000} }));
const authLimiter = rateLimit({windowMs:15*60*1000,limit:8,standardHeaders:'draft-8',legacyHeaders:false});
app.use('/api/',rateLimit({windowMs:60*1000,limit:120,standardHeaders:'draft-8',legacyHeaders:false}));
function asyncRoute(fn){return (req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next);}
function csrf(req){if(!req.session.csrfToken)req.session.csrfToken=crypto.randomBytes(32).toString('base64url');return req.session.csrfToken;}
function requireCsrf(req,res,next){
  const sent=req.get('x-csrf-token'),expected=req.session.csrfToken;
  if(!sent||!expected||sent.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(sent),Buffer.from(expected)))
    return res.status(403).json({error:'CSRF_VALIDATION_FAILED',requestId:req.requestId});
  next();
}
function requireUser(req,res,next){if(!req.session.userId)return res.status(401).json({error:'AUTHENTICATION_REQUIRED',requestId:req.requestId});next();}
async function audit(userId,eventType,req,metadata={}){
  await pool.query('INSERT INTO security_audit_events(user_id,event_type,request_id,metadata) VALUES($1,$2,$3,$4)',
    [userId||null,eventType,req.requestId,JSON.stringify(metadata)]);
}
function publicUser(row){return{id:row.id,email:row.email,status:row.status,emailVerified:Boolean(row.email_verified_at)};}
function rotateSession(req,userId){
  return new Promise((resolve,reject)=>req.session.regenerate(err=>{
    if(err)return reject(err);req.session.userId=userId;req.session.csrfToken=crypto.randomBytes(32).toString('base64url');resolve();
  }));
}
app.get('/healthz',asyncRoute(async(_req,res)=>{await pool.query('SELECT 1');res.json({status:'ok',database:'ok'});}));
app.get('/api/auth/csrf',(req,res)=>{res.setHeader('Cache-Control','no-store');res.json({csrfToken:csrf(req)});});
const registerSchema=z.object({email:z.string().trim().email().max(254),password:z.string().min(12).max(128)}).strict();
app.post('/api/auth/register',authLimiter,requireCsrf,asyncRoute(async(req,res)=>{
  const input=registerSchema.parse(req.body),email=input.email.toLowerCase();
  const hash=await argon2.hash(input.password,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});
  let user;
  try{user=(await pool.query('INSERT INTO app_users(email,password_hash) VALUES($1,$2) RETURNING id,email,status,email_verified_at',[email,hash])).rows[0];}
  catch(e){if(e.code==='23505')return res.status(409).json({error:'ACCOUNT_ALREADY_EXISTS'});throw e;}
  await rotateSession(req,user.id);await audit(user.id,'auth.register',req);
  res.status(201).setHeader('Cache-Control','no-store').json({user:publicUser(user),csrfToken:req.session.csrfToken});
}));
const loginSchema=z.object({email:z.string().trim().email().max(254),password:z.string().min(1).max(128)}).strict();
app.post('/api/auth/login',authLimiter,requireCsrf,asyncRoute(async(req,res)=>{
  const input=loginSchema.parse(req.body);
  const user=(await pool.query('SELECT id,email,password_hash,status,email_verified_at FROM app_users WHERE email=$1',[input.email.toLowerCase()])).rows[0];
  const valid=user&&user.status==='active'&&await argon2.verify(user.password_hash,input.password).catch(()=>false);
  if(!valid){await audit(null,'auth.login_failed',req);return res.status(401).json({error:'INVALID_CREDENTIALS'});}
  await rotateSession(req,user.id);await audit(user.id,'auth.login',req);
  res.setHeader('Cache-Control','no-store').json({user:publicUser(user),csrfToken:req.session.csrfToken});
}));
app.get('/api/auth/me',requireUser,asyncRoute(async(req,res)=>{
  const result=await pool.query('SELECT id,email,status,email_verified_at FROM app_users WHERE id=$1',[req.session.userId]);
  if(!result.rowCount||result.rows[0].status!=='active')return req.session.destroy(()=>res.status(401).json({error:'AUTHENTICATION_REQUIRED'}));
  res.setHeader('Cache-Control','no-store').json({user:publicUser(result.rows[0]),csrfToken:csrf(req)});
}));
app.post('/api/auth/logout',requireUser,requireCsrf,asyncRoute(async(req,res)=>{
  await audit(req.session.userId,'auth.logout',req);
  req.session.destroy(err=>{if(err)return res.status(500).json({error:'LOGOUT_FAILED',requestId:req.requestId});
    res.clearCookie(production?'__Host-california.sid':'california.sid',{path:'/',httpOnly:true,secure:production,sameSite:'lax'});res.status(204).end();});
}));
app.get('/api/banking/status',requireUser,asyncRoute(async(req,res)=>{
  const row=(await pool.query('SELECT onboarding_status FROM banking_customers WHERE user_id=$1',[req.session.userId])).rows[0];
  res.setHeader('Cache-Control','no-store').json({provider:'Unit',providerConfigured:Boolean(process.env.UNIT_API_TOKEN),
    programEnabled:process.env.UNIT_PROGRAM_ENABLED==='true',environment:process.env.UNIT_ENV||'sandbox',
    onboardingStatus:row?row.onboarding_status:'not_started',moneyMovementEnabled:false,
    message:'Banking actions remain disabled until provider onboarding, approved program credentials, and webhook verification are configured.'});
}));
app.get('/api/accounts',requireUser,asyncRoute(async(req,res)=>{
  const result=await pool.query('SELECT id,account_type,status,currency,available_balance_cents,current_balance_cents,last_synced_at FROM bank_accounts WHERE user_id=$1 ORDER BY created_at DESC',[req.session.userId]);
  res.setHeader('Cache-Control','no-store').json({accounts:result.rows});
}));
app.get('/api/transactions',requireUser,asyncRoute(async(req,res)=>{
  const limit=Math.min(100,Math.max(1,Number(req.query.limit)||25));
  const result=await pool.query('SELECT t.id,t.account_id,t.amount_cents,t.currency,t.direction,t.status,t.description,t.effective_at FROM bank_transactions t WHERE t.user_id=$1 ORDER BY t.effective_at DESC NULLS LAST,t.created_at DESC LIMIT $2',[req.session.userId,limit]);
  res.setHeader('Cache-Control','no-store').json({transactions:result.rows});
}));
app.post('/api/transfers',requireUser,requireCsrf,asyncRoute(async(req,res)=>{
  await audit(req.session.userId,'banking.transfer_blocked',req,{reason:'provider_program_not_enabled'});
  res.status(503).json({error:'BANKING_PROGRAM_NOT_READY',message:'Transfers are unavailable until the approved banking provider integration is enabled and verified.'});
}));
app.post('/api/webhooks/unit',asyncRoute(async(req,res)=>{
  const secret=process.env.UNIT_WEBHOOK_SECRET;
  if(!secret||secret.length<32)return res.status(503).json({error:'WEBHOOK_VERIFICATION_NOT_CONFIGURED'});
  if(!Buffer.isBuffer(req.body))return res.status(400).json({error:'INVALID_WEBHOOK_BODY'});
  const signature=req.get('x-unit-signature')||'';
  const expected=crypto.createHmac('sha1',secret).update(req.body).digest();
  let supplied;
  try{supplied=Buffer.from(signature,'base64');}catch(_){return res.status(401).json({error:'INVALID_WEBHOOK_SIGNATURE'});}
  if(supplied.length!==expected.length||!crypto.timingSafeEqual(supplied,expected))
    return res.status(401).json({error:'INVALID_WEBHOOK_SIGNATURE'});
  let payload;
  try{payload=JSON.parse(req.body.toString('utf8'));}catch(_){return res.status(400).json({error:'INVALID_WEBHOOK_JSON'});}
  const events=Array.isArray(payload.data)?payload.data:(payload.data?[payload.data]:[]);
  if(!events.length||events.length>64)return res.status(400).json({error:'INVALID_WEBHOOK_EVENTS'});
  let accepted=0,duplicates=0;
  for(const event of events){
    const eventId=String(event.id||'').trim(),eventType=String(event.type||'').trim();
    if(!eventId||!eventType||eventId.length>255||eventType.length>255)
      return res.status(400).json({error:'WEBHOOK_EVENT_ID_AND_TYPE_REQUIRED'});
    const saved=await pool.query(
      'INSERT INTO provider_webhook_events(provider,provider_event_id,event_type) VALUES($1,$2,$3) ON CONFLICT(provider,provider_event_id) DO NOTHING RETURNING provider_event_id',
      ['unit',eventId,eventType]);
    if(saved.rowCount){accepted++;await audit(null,'provider.unit.webhook_received',req,{eventId,eventType});}
    else duplicates++;
  }
  res.status(200).json({received:true,accepted,duplicates});
}));
app.use('/api',(req,res)=>res.status(404).json({error:'NOT_FOUND',requestId:req.requestId}));
app.use(express.static(path.join(process.cwd(),'public'),{index:'index.html',maxAge:production?'1h':0,etag:true}));
app.get('/{*path}',(_req,res)=>res.sendFile(path.join(process.cwd(),'public','index.html')));
app.use((err,req,res,_next)=>{
  if(err instanceof z.ZodError)return res.status(400).json({error:'INVALID_REQUEST',issues:err.issues.map(i=>({path:i.path,code:i.code}))});
  if(err&&err.type==='entity.parse.failed')return res.status(400).json({error:'INVALID_JSON'});
  console.error('Request failed',{requestId:req.requestId,message:err.message});
  if(!res.headersSent)res.status(500).json({error:'INTERNAL_SERVER_ERROR',requestId:req.requestId});
});
const server=app.listen(port,()=>console.log('California Bank API listening on '+port));
async function shutdown(signal){console.log('Received '+signal+'; shutting down');server.close(async()=>{await pool.end();process.exit(0);});setTimeout(()=>process.exit(1),10000).unref();}
process.on('SIGTERM',()=>shutdown('SIGTERM'));process.on('SIGINT',()=>shutdown('SIGINT'));
module.exports={app,pool};
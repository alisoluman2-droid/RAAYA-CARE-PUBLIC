'use strict';
const crypto = require('node:crypto');
const admin = require('firebase-admin');
const databaseURL = 'https://raaya-care-09nov-default-rtdb.europe-west1.firebasedatabase.app';
const respond = (statusCode, data) => ({statusCode, headers:{'Content-Type':'application/json','Cache-Control':'no-store','Pragma':'no-cache'},body:JSON.stringify(data)});
const normalizePhone = value => {
  const s=String(value||'').trim().replace(/[\s()+-]/g,'').replace(/^(?:00)?(?:970|972)/,'').replace(/^0/,'');
  return /^5\d{8}$/.test(s)?s:null;
};
const aliasFor = phone => 'employee-'+crypto.createHash('sha256').update(phone).digest('hex').slice(0,40)+'@login.raaya.invalid';
const validKey = v => typeof v==='string' && /^[A-Za-z0-9_-]{1,120}$/.test(v);
const accepted = r => r && ['مقبول','مقبولة','accepted'].includes(String(r.status||'').trim());
exports.handler=async event=>{
  if(event.httpMethod!=='POST')return respond(405,{error:'method'});
  const match=/^Bearer ([^\s]+)$/i.exec(event.headers?.authorization||event.headers?.Authorization||'');
  if(!match)return respond(401,{error:'unauthorized'});
  let input;try{if((event.body||'').length>2048)throw Error();input=JSON.parse(event.body||'{}')}catch{return respond(400,{error:'invalid_request'})}
  if(!input||!validKey(input.uid)||!validKey(input.jobId))return respond(400,{error:'invalid_request'});
  try{
    const permitted=[process.env.RAAYA_ALI_UID,process.env.RAAYA_SAMAR_UID].filter(Boolean);
    if(!permitted.length||!process.env.FIREBASE_SERVICE_ACCOUNT_JSON)return respond(503,{error:'configuration'});
    const app=admin.apps.find(a=>a?.name==='employee-auth')||admin.initializeApp({credential:admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON)),databaseURL},'employee-auth');
    const auth=app.auth();let caller;
    try{caller=await auth.verifyIdToken(match[1],true)}catch{return respond(401,{error:'unauthorized'})}
    if(!permitted.includes(caller.uid)||caller.firebase?.sign_in_provider==='anonymous'||permitted.includes(input.uid))return respond(403,{error:'forbidden'});
    const jobs=(await app.database().ref('raayaShared/jobs').get()).val()||{};
    const job=jobs[input.uid]?.[input.jobId];
    if(!accepted(job)||job.ownerUid!==input.uid||String(job.sourceId)!==input.jobId)return respond(409,{error:'not_approved'});
    const phone=normalizePhone(job.phone||job.phoneNumber||job.mobile);
    if(!phone)return respond(409,{error:'invalid_phone'});
    for(const [uid,records] of Object.entries(jobs)){
      if(uid!==input.uid&&Object.values(records||{}).some(r=>accepted(r)&&normalizePhone(r.phone||r.phoneNumber||r.mobile)===phone))return respond(409,{error:'duplicate_phone'});
    }
    let user;try{user=await auth.getUser(input.uid)}catch(e){if(e.code==='auth/user-not-found')return respond(409,{error:'missing_account'});throw e}
    if(user.disabled)return respond(409,{error:'disabled_account'});
    const email=aliasFor(phone);
    // Never overwrite an unrelated login provider or move data to another UID.
    if((user.email&&user.email!==email)||(user.providerData||[]).some(p=>p.providerId!=='password'))return respond(409,{error:'existing_provider'});
    const password='Aa9!'+crypto.randomBytes(18).toString('base64url');
    try{await auth.updateUser(input.uid,{email,password,emailVerified:false})}catch(e){if(e.code==='auth/email-already-exists')return respond(409,{error:'duplicate_phone'});throw e}
    await auth.revokeRefreshTokens(input.uid);
    return respond(200,{success:true,password});
  }catch(e){console.error('RAAYA employee credential setup failed:',e.code||'internal');return respond(500,{error:'setup_failed'})}
};

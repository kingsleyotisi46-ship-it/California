'use strict';
let csrfToken='';let mode='login';
const $=s=>document.querySelector(s);
const authView=$('#auth-view');const accountView=$('#account-view');const form=$('#auth-form');const notice=$('#notice');const logout=$('#logout');let currentUser=null;
async function api(path,options={}){
 const headers={'Content-Type':'application/json',...(options.headers||{})};
 if(csrfToken&&!['GET','HEAD'].includes((options.method||'GET').toUpperCase()))headers['X-CSRF-Token']=csrfToken;
 const response=await fetch(path,{credentials:'same-origin',cache:'no-store',...options,headers});
 if(response.status===204)return null;
 const data=await response.json().catch(()=>({}));
 if(!response.ok){const e=new Error(data.message||data.error||'Request failed');e.status=response.status;throw e;}
 if(data.csrfToken)csrfToken=data.csrfToken;return data;
}
function showNotice(message,isError=false){notice.hidden=!message;notice.textContent=message||'';notice.classList.toggle('error',isError);}
function setMode(next){
 mode=next;
 $('#auth-title').textContent=mode==='login'?'Welcome back':'Create your account';
 $('.auth-content > .muted').textContent=mode==='login'?'Sign in to securely access your account.':'Open your California Bank profile with your real details.';
 $('#submit').innerHTML=(mode==='login'?'Sign in securely':'Create account')+' <span aria-hidden="true">→</span>';
 $('#password').autocomplete=mode==='login'?'current-password':'new-password';
 $('#profile-fields').hidden=mode==='login';
 $('#confirm-field').hidden=mode==='login';
 $('#terms-field').hidden=mode==='login';
 $('#first-name').required=mode==='register';
 $('#last-name').required=mode==='register';
 $('#phone-number').required=mode==='register';
 $('#confirm-password').required=mode==='register';
 $('#terms-accepted').required=mode==='register';
 $('#email').autocomplete='email';
 $('#toggle-mode').textContent=mode==='login'?'Create an account':'Sign in';
 showNotice('');
}
function escapeHtml(value){return String(value).replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));}
function money(cents,currency='USD'){
 const n=Number(cents);if(!Number.isSafeInteger(n))return 'Unavailable';
 try{return new Intl.NumberFormat('en-US',{style:'currency',currency}).format(n/100);}catch(_){return 'Unavailable';}
}
function renderEmpty(el,message){el.innerHTML='<div class="empty">'+escapeHtml(message)+'</div>';}
async function refreshBankingData(){
 const [ar,tr]=await Promise.all([api('/api/accounts'),api('/api/transactions')]);
 const accounts=ar.accounts||[],transactions=tr.transactions||[];
 $('#account-count').textContent=accounts.length+' linked';
 $('#accounts').innerHTML=accounts.length?accounts.map(a=>{
   const balance=a.available_balance_cents==null?'Balance unavailable':money(a.available_balance_cents,a.currency);
   return '<article class="account-tile"><div class="account-tile-head"><span class="account-type">'+escapeHtml(a.account_type||'Bank account')+'</span><span class="account-state">'+escapeHtml(a.status||'Status unavailable')+'</span></div><div class="account-balance-label">Available balance</div><div class="account-balance">'+escapeHtml(balance)+'</div><div class="account-currency">'+escapeHtml(a.currency||'USD')+' · Provider-linked account</div></article>';
 }).join(''):'<div class="empty">No provider-linked accounts are available yet. Once a banking account is approved and linked, it will appear here.</div>';
 $('#transactions').innerHTML=transactions.length?transactions.map(t=>{
   const credit=t.direction==='credit';
   return '<div class="data-row"><span><strong>'+escapeHtml(t.description||'Bank transaction')+'</strong><small>'+escapeHtml(t.effective_at?new Date(t.effective_at).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'}):'Date pending')+' · '+escapeHtml(t.status||'Confirmed')+'</small></span><span class="amount '+(credit?'credit':'')+'">'+(credit?'+':'−')+escapeHtml(money(t.amount_cents,t.currency))+'</span></div>';
 }).join(''):'<div class="empty">No provider-confirmed transactions are available yet. Your activity will appear here after the provider confirms it.</div>';
}
function showPage(page){
 const pages={overview:$('#overview-page'),profile:$('#profile-page'),activity:$('#activity-page'),transfers:$('#transfers-page'),cards:$('#cards-page'),loans:$('#loans-page'),bills:$('#bills-page'),topup:$('#topup-page'),support:$('#support-page')};
 Object.entries(pages).forEach(([key,el])=>{el.hidden=key!==page;});
 document.querySelectorAll('[data-page]').forEach(btn=>{const active=btn.dataset.page===page;btn.classList.toggle('nav-active',active);btn.setAttribute('aria-current',active?'page':'false');});
 const titles={overview:'Welcome to your dashboard',profile:'My profile',activity:'Account activity',transfers:'Transfers',cards:'Cards',loans:'Loans',bills:'Utility bills',topup:'Mobile top-up',support:'Help & support'};
 document.querySelector('.topbar h1').textContent=titles[page]||titles.overview;
}
async function loadAccount(){
 const {user}=await api('/api/auth/me');currentUser=user;
 authView.hidden=true;accountView.hidden=false;logout.hidden=false;
 $('#account-email').textContent=user.email;
 $('#profile-name').textContent=[user.firstName,user.middleName,user.lastName].filter(Boolean).join(' ')||'Not provided';
 $('#profile-email').textContent=user.email||'—';
 $('#profile-phone').textContent=user.phoneNumber||'Not provided';
 $('#profile-account-number').textContent=user.accountNumber||'Not assigned';
 $('#profile-status').textContent=user.status||'Unknown';
 showPage('overview');
 const s=await api('/api/banking/status');
 const ready=Boolean(s.providerConfigured&&s.programEnabled&&s.onboardingStatus==='approved');
 $('#bank-status-title').textContent=ready?'Banking provider connected':'Banking setup pending';
 $('#bank-status-badge').textContent=ready?'CONNECTED':'PENDING';
 $('#bank-status-badge').classList.toggle('ready',ready);
 $('#bank-status-text').textContent=s.message;
 await refreshBankingData();
}
function showAuth(){accountView.hidden=true;authView.hidden=false;logout.hidden=true;currentUser=null;}
form.addEventListener('submit',async e=>{
 e.preventDefault();const button=$('#submit');button.disabled=true;showNotice('');
 try{
  const payload={email:$('#email').value.trim(),password:$('#password').value};
  if(mode==='register'){
   if(payload.password!==$('#confirm-password').value){showNotice('Your passwords do not match.',true);return;}
   if(!$('#terms-accepted').checked){showNotice('Please read and accept the Terms of Service and Privacy Policy.',true);return;}
   Object.assign(payload,{firstName:$('#first-name').value.trim(),middleName:$('#middle-name').value.trim(),lastName:$('#last-name').value.trim(),phoneNumber:$('#phone-number').value.trim(),confirmPassword:$('#confirm-password').value,termsAccepted:true});
  }
  const result=await api('/api/auth/'+(mode==='login'?'login':'register'),{method:'POST',body:JSON.stringify(payload)});
  csrfToken=result.csrfToken;form.reset();await loadAccount();
 }catch(err){
  showNotice(err.status===409?'An account with this email already exists. Sign in instead.':err.status===401?'Email or password is incorrect.':err.status===400?'Check your details, make sure passwords match, and use at least 12 password characters.':'We could not complete this request. Please try again.',true);
 }finally{button.disabled=false;}
});
document.querySelectorAll('[data-page]').forEach(btn=>btn.addEventListener('click',async()=>{
 if(!currentUser)return;
 showPage(btn.dataset.page);
 if(btn.dataset.page==='activity'){
  const target=$('#activity-transactions');
  target.innerHTML=$('#transactions').innerHTML;
  try{await refreshBankingData();target.innerHTML=$('#transactions').innerHTML;}
  catch(_){renderEmpty(target,'Unable to load confirmed activity. Please try again.');}
 }
}));
async function refreshActivityPage(){
 const button=$('#activity-refresh');button.disabled=true;
 try{await refreshBankingData();$('#activity-transactions').innerHTML=$('#transactions').innerHTML;}
 catch(_){renderEmpty($('#activity-transactions'),'Unable to load confirmed activity. Please try again.');}
 finally{button.disabled=false;}
}
$('#activity-refresh').addEventListener('click',refreshActivityPage);
$('#toggle-mode').addEventListener('click',()=>setMode(mode==='login'?'register':'login'));
logout.addEventListener('click',async()=>{
 try{await api('/api/auth/logout',{method:'POST',body:'{}'});}catch(_){}
 csrfToken='';showAuth();setMode('login');
});
$('#refresh').addEventListener('click',async()=>{
 const button=$('#refresh');button.disabled=true;
 try{await refreshBankingData();}catch(_){const n=document.createElement('div');n.className='empty';n.textContent='Unable to refresh provider data right now. Please try again.';$('#transactions').replaceChildren(n);}
 finally{button.disabled=false;}
});
(async function init(){
 showAuth();
 try{const c=await api('/api/auth/csrf');csrfToken=c.csrfToken;await loadAccount();}
 catch(e){if(e.status!==401)showNotice('Secure service is temporarily unavailable. Refresh and try again.',true);}
})();
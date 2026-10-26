// Isolated rendering checks for the shipped script, with no real browser or network.
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
class Element {
  constructor(tag) { this.tag=tag;this.children=[];this.textContent='';this.events={}; }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children=items; }
  setAttribute() {}
  addEventListener(name, handler) { this.events[name]=handler; }
  set innerHTML(value) { throw new Error('Unsafe HTML insertion'); }
}
const elements = new Map();
const document = {
  hidden:false,
  getElementById(id) { if(!elements.has(id))elements.set(id,new Element('div'));return elements.get(id); },
  createElement:tag=>new Element(tag), createTextNode:text=>text,
  addEventListener() {}
};
const snapshot = {
 rows:[{device_id:'test-unit',alias:'<img src=x onerror=BAD()>',
  gps:{check_state:'request_failed',checked_at_utc:'2026-10-26T10:00:00Z',
   attempted_at_utc:'2026-10-26T11:00:00Z',last_success:{reported_at_utc:'2026-10-26T09:00:00Z',valid_coordinate_bounds:true}},
  history:[{at_utc:'2026-10-26T11:00:00Z',check:'gps',outcome:'API check failed'}]}],
 collecting:false,device_count:1,device_limit:50,camera_devices:[],camera_consent:true,
 csrf:'test-csrf',expires_at_utc:'2026-10-26T12:00:00Z'
};
let sent, unauthorized=false;
const context = vm.createContext({document,Date,Set,URLSearchParams,setInterval(){},
 location:{assign(){}},fetch:async (path,options)=>{
  if(path.endsWith('/action')){sent=options;return {ok:true,json:async()=>({configured:true})};}
  return {ok:!unauthorized,json:async()=>unauthorized?{error:'Sign in again'}:snapshot};
 }});
vm.runInContext(fs.readFileSync(process.argv[2],'utf8'), context);
const flush=()=>new Promise(resolve=>setImmediate(resolve));
const text = e=>typeof e==='string'?e:e.textContent+' '+e.children.map(text).join(' ');
(async()=>{
 await flush();
 assert.equal(elements.get('total').textContent,1);
 assert.equal(elements.get('failed').textContent,1);
 assert.match(text(elements.get('units')),/API check failed/);
 assert.match(text(elements.get('units')),/<img src=x onerror=BAD\(\)>/);
 vm.runInContext("detailId='test-unit';renderDetail()",context);
 assert.match(text(elements.get('detail')),/not end-to-end delivery delay/);
 await vm.runInContext("action({action:'configure',device:['test-unit']})",context);
 assert.equal(sent.body.get('csrf'),'test-csrf');
 assert.equal(sent.body.get('device'),'test-unit');
 unauthorized=true;
 await vm.runInContext('load()',context);
 assert.equal(elements.get('units').children.length,0);
 assert.equal(elements.get('detail').hidden,true);
 assert.equal(elements.get('total').textContent,'—');
 console.log('Dashboard rendering checks passed: safe text, stale evidence, CSRF submission and revoked-access clearing.');
})().catch(error=>{console.error(error);process.exitCode=1;});

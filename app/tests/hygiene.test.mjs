import {test} from 'node:test';
import assert from 'node:assert/strict';
import {deviceInventoryReady,renderDeviceProbe,createHygienePanel,hygieneStats,renderHygiene} from '../dist/hygiene.js';
class Element{
  children=[];textContent='';dataset={};hidden=false;
  constructor(tag){this.tag=tag;}
  append(...items){this.children.push(...items);}
  replaceChildren(...items){this.children=items;}
  all(tag){return this.children.flatMap(c=>[...(c.tag===tag?[c]:[]),...c.all(tag)]);}
}
test('device inventory does not permit remote work with missing, failed, stale or future observations',()=>{
  const good={last_attempt:1000,last_success:1000,protected_values:4,unavailable:[],code:null};
  assert.equal(deviceInventoryReady(good,1001),true);
  for(const status of [undefined,{...good,unavailable:['wifi']},{...good,code:'probe_failed'},{...good,last_success:0},{...good,last_success:1002}])assert.equal(deviceInventoryReady(status,1001),false);
  assert.equal(deviceInventoryReady(good,87400),false);
});
test('unknown hygiene points remain in the denominator and cannot make an unmeasured score green',()=>{
  const checks=['wifi_mac','hostname','multicast','location','clock','browser'].map(kind=>({kind,verdict:'unknown'}));
  const report={checks,llmnr_disabled:true,netbios_disabled:null,mdns_disabled:null};
  assert.deepEqual(hygieneStats(report),{known:0,passed:0,score:null});checks[0].verdict='pass';assert.deepEqual(hygieneStats(report),{known:1,passed:1,score:1/6});
  const previous=globalThis.document;globalThis.document={createElement:tag=>new Element(tag)};
  try{const root=new Element('div');renderHygiene(root,{last_attempt:1,last_success:1,protected_values:0,unavailable:[],code:null,hygiene:report});assert.ok(root.all('p').some(p=>p.textContent.includes('hygiene_score: неизвестно')));assert.equal(root.all('li').length,6);}finally{globalThis.document=previous;}
  assert.throws(()=>hygieneStats({...report,checks:[...checks.slice(0,5),{kind:'<script>',verdict:'pass'}]}));
});
test('hygiene UI keeps untrusted source labels as text and distinguishes manual instructions from OS observations',()=>{
  const previous=globalThis.document;globalThis.document={createElement:tag=>new Element(tag)};
  try{
    const root=new Element('div');renderDeviceProbe(root,{last_attempt:0,last_success:0,protected_values:0,unavailable:['<script>synthetic</script>'],code:'<img>'});
    assert.equal(root.all('script').length,0);assert.equal(root.all('img').length,0);
    assert.ok(root.all('li').some(item=>item.textContent.includes('<script>synthetic</script>')));
    const page=createHygienePanel();assert.equal(page.dataset.panel,'hygiene');assert.equal(page.all('input').length,0);
    assert.ok(page.all('p').some(p=>p.textContent.includes('не реализованы')));assert.equal(page.all('li').length,6);
    renderDeviceProbe(root,undefined);assert.equal(root.all('li').length,0);
  }finally{globalThis.document=previous;}
});

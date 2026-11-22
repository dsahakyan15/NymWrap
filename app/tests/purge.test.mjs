import {test} from 'node:test';
import assert from 'node:assert/strict';
import {renderPurgeGuide,renderPurgeBatches} from '../dist/purge.js';
class Element{
  children=[];textContent='';listeners=new Map();checked=false;value='';
  constructor(tag){this.tag=tag;}
  append(...items){this.children.push(...items);}
  replaceChildren(...items){this.children=items;}
  addEventListener(name,fn){this.listeners.set(name,fn);}
  all(tag){return this.children.flatMap(c=>[...(c.tag===tag?[c]:[]),...c.all(tag)]);}
}
test('Purge renders untrusted values as text and records only an explicit user report',async()=>{
  const previous=globalThis.document;globalThis.document={createElement:tag=>new Element(tag)};
  try{
    const root=new Element('div'),guide={service:'google',checked_on:'2026-11-22',steps:[{id:'history',title:'History',text:'<script>synthetic data</script>'},{id:'verify',title:'Verify',text:'Check again'}],sources:[{title:'Official',url:'https://support.google.com/'}]};
    renderPurgeGuide(root,guide);assert.equal(root.all('script').length,0);assert.ok(root.all('p').some(p=>p.textContent==='<script>synthetic data</script>'));
    const saved=[];renderPurgeBatches(root,[{hash:'a'.repeat(64),batch:{service:'google',record_ids:['synthetic-record']},review:null}],new Map([['google',guide]]),async(...args)=>{saved.push(args);},()=>assert.fail('save_failed'));
    assert.equal(saved.length,0);assert.ok(root.all('p').some(p=>p.textContent.includes('NymWrap')));
    for(const input of root.all('input'))input.checked=true;
    root.all('select')[0].value='no_longer_visible';root.all('button')[0].listeners.get('click')();
    await new Promise(resolve=>setImmediate(resolve));
    assert.deepEqual(saved,[['a'.repeat(64),'no_longer_visible',['history','verify']]]);
    assert.equal(root.all('a').length,0);
  }finally{globalThis.document=previous;}
});

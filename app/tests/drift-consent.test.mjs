import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createAiWebConsent} from '../dist/drift-consent.js';
test('AI consent is unchecked by default and its associated label warns about service terms and account blocking',()=>{
  const previous=globalThis.document;
  globalThis.document={createElement:tag=>({tag,children:[],append(...children){this.children.push(...children);}}),createTextNode:text=>({text})};
  try{
    for(const enabled of [undefined,false,'true',1,{},true]){
      const {label,input}=createAiWebConsent(enabled);
      assert.equal(input.checked,enabled===true);assert.equal(input.type,'checkbox');assert.equal(label.children[0],input);
      const warning=label.children[1].text;
      assert.match(warning,/Предупреждение/);assert.match(warning,/условия сервиса/);assert.match(warning,/блокировке аккаунта/);assert.match(warning,/локальных синтетических/);
    }
  }finally{globalThis.document=previous;}
});

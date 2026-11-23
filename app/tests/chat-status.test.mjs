import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chatStatusLabel} from '../dist/chat-status.js';
test('the local privacy reason is visible without changing a structured model answer',()=>{
  const reply={trust:'L0',text:'{"answer":42}',local_reason:'independent_split_unavailable'};
  assert.match(chatStatusLabel(reply),/совокупность фактов может выдать/);
  assert.deepEqual(JSON.parse(reply.text),{answer:42});
  assert.equal(chatStatusLabel({trust:'L0'}),'Ответ получен локально (L0).');
  assert.ok(!chatStatusLabel({trust:'L0',local_reason:'<img src=x onerror=SECRET>'}).includes('SECRET'));
  assert.ok(!chatStatusLabel({trust:'L3',local_reason:'missing_dossier'}).includes('Досье'));
  for(const local_reason of ['constructor','toString','__proto__'])assert.match(chatStatusLabel({trust:'L0',local_reason}),/Проверка приватности/);
});

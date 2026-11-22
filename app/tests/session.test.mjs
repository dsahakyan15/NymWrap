import{test}from 'node:test';
import assert from 'node:assert/strict';
import{sessionTimingLabel}from '../dist/session.js';
test('session boundary messages distinguish local availability, queued traffic, locked and background state',()=>{
  const status={phase:'starting',first_send_in_s:301,tail_remaining_s:null};
  assert.match(sessionTimingLabel(status),/6 мин/);
  assert.match(sessionTimingLabel(status),/Локальные ответы доступны/);
  assert.match(sessionTimingLabel({...status,phase:'tail',tail_remaining_s:601}),/11 мин/);
  assert.match(sessionTimingLabel({...status,phase:'locked',first_send_in_s:0}),/остановлен/);
  for(const bad of [{...status,first_send_in_s:NaN},{...status,first_send_in_s:1801},{...status,tail_remaining_s:3601},{...status,phase:'<script>canary</script>'}])assert.throws(()=>sessionTimingLabel(bad));
});

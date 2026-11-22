import {test}from 'node:test';
import assert from 'node:assert/strict';
import{activityTransition,activityLabel}from '../dist/activity.js';
test('UTC activity controls reject missing, fractional, out-of-range and nonnumeric values',()=>{
  assert.deepEqual(activityTransition(22,2,4),{start_hour_utc:22,target_hour_utc:2,width_hours:4});
  for(const values of [[NaN,2,4],[0,24,6],[0,2,0],[0,2,13],[0,2,1.5],[-1,2,4]])assert.throws(()=>activityTransition(...values));
});
test('plan review displays a wrapping UTC window and identifies legacy plans',()=>{
  assert.match(activityLabel({windows:[{start_hour_utc:22,width_hours:4}]},0),/22:00–02:00 UTC/);
  assert.match(activityLabel(null,0),/Прежний план без окна/);
  assert.throws(()=>activityLabel({windows:[{start_hour_utc:99,width_hours:4}]},0));
});

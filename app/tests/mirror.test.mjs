import {test} from 'node:test';
import assert from 'node:assert/strict';
import {timeline,sourceName} from '../dist/mirror.js';
test('Mirror separates sources, preserves rollback and overshoot, and orders actual timestamps',()=>{
  const data=timeline([{kind:'ad_topics',captured_at:300,position:1.4},{kind:'youtube_feed',captured_at:100,position:-.3},{kind:'youtube_feed',captured_at:200,position:.4}]);
  assert.equal(data.series.length,2);assert.equal(data.start,100);assert.equal(data.end,300);
  assert.ok(data.series[0].points[0].x<data.series[0].points[1].x);
  assert.ok(data.series[0].points[0].y>data.baseline);
  assert.ok(data.series[1].points[0].y<data.target);
});
test('Mirror handles one point, extreme finite values, and rejects invalid or foreign source data',()=>{
  const one=timeline([{kind:'ai_memory',captured_at:1,position:.6}]);assert.equal(one.series[0].points[0].x,380);
  const data=timeline([{kind:'ai_memory',captured_at:1,position:Number.MAX_VALUE},{kind:'ai_memory',captured_at:2,position:-Number.MAX_VALUE},{kind:'__proto__',captured_at:2,position:.1},{kind:'ad_topics',captured_at:2,position:NaN}]);
  assert.equal(data.series.length,1);assert.equal(data.series[0].points.length,2);
  for(const p of data.series[0].points)assert.ok(Number.isFinite(p.x)&&Number.isFinite(p.y));
  assert.equal(sourceName('<script>data</script>'),'Неизвестный источник');assert.equal(timeline([]).series.length,0);
});

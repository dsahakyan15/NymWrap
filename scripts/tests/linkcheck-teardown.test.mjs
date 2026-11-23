import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {finishEvaluation} from '../linkcheck-eval.mjs';

test('evaluation teardown observes child exit, including a forced stop, before it returns',async()=>{
  for(const graceful of [true,false]){
    const child=spawn(process.execPath,['-e',graceful?"process.stdout.write('ready');setTimeout(()=>process.exit(0),50);":"process.stdout.write('ready');setInterval(()=>{},1000);"],{windowsHide:true,stdio:['ignore','pipe','ignore']});
    try{
      await once(child.stdout,'data');
      await finishEvaluation(child);
      assert.ok(child.exitCode!==null||child.signalCode!==null);
      if(graceful)assert.equal(child.exitCode,0);
      await finishEvaluation(child);
    }finally{if(child.exitCode===null&&child.signalCode===null){child.kill();await once(child,'exit');}}
  }
});

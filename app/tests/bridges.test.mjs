import{test}from'node:test';import assert from'node:assert/strict';
import{bridgeInput,bridgeStatusLabel}from'../dist/bridges.js';
test('bridge controls need explicit lines and display only bounded status metadata',()=>{
 assert.equal(bridgeInput('disabled','PRIVATE_BRIDGE_CANARY'),null);
 assert.deepEqual(bridgeInput('webtunnel',' synthetic line\r\n\n'),{transport:'webtunnel',lines:['synthetic line']});
 for(const [kind,text]of [['exec','synthetic'],['obfs4',''],['obfs4','same\nsame'],['webtunnel','x'.repeat(4097)]])assert.throws(()=>bridgeInput(kind,text));
 assert.match(bridgeStatusLabel({transport:'obfs4',lines:2,isolation_supported:true}),/строк мостов: 2/);
 assert.match(bridgeStatusLabel({transport:'obfs4',lines:2,isolation_supported:false}),/запуск мостов запрещён/);
 assert.throws(()=>bridgeStatusLabel({transport:'<script>',lines:1}));assert.throws(()=>bridgeStatusLabel({transport:'obfs4',lines:17}));
});

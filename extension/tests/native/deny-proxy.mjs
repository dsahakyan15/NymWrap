// Fixture only: deny every browser connection without opening an upstream socket.
import net from 'node:net';

export async function startDenyProxy(){
  const sockets=new Set();let failure,resets=0;
  const server=net.createServer(socket=>{
    sockets.add(socket);
    socket.on('close',()=>sockets.delete(socket));
    socket.on('error',error=>{
      // Firefox may abort a refused CONNECT or close it while quitting. This is
      // the accepted proxy socket, independent of Marionette and native stdio.
      if(error.code==='ECONNRESET'){resets++;return;}
      failure??=error;
    });
    socket.resume();
    socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
  });
  server.on('error',error=>{failure??=error;});
  await new Promise((accept,reject)=>{
    server.once('error',reject);
    server.listen(0,'127.0.0.1',()=>{server.removeListener('error',reject);accept();});
  });
  return {
    port:server.address().port,
    get resets(){return resets;},
    async close(){
      const closed=new Promise((accept,reject)=>server.close(error=>error?reject(error):accept()));
      for(const socket of sockets)socket.destroy();
      await closed;
      // Unexpected socket/listener errors still fail the fixture after cleanup.
      if(failure)throw failure;
    }
  };
}

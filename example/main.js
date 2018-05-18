const dnsprove = require('./../index.js');
dnsprove.queryWithProof('TXT', '_ens.matoken.xyz').then((results, error)=>{
    results.forEach((result)=>{
      console.log(dnsprove.display(result[0]));
      result[1].forEach((r)=>{
        console.log(dnsprove.display(r));
      })
      packed1 = dnsprove.pack(result[1], result[0])
      packed = packed1.map((p)=>{
        return p.toString('hex')
      });
      var name = result[0].name;
      if(name != '.'){
        name = name +  '.';
      }
      var data = packed[0];
      var sig = packed[1];
      packed.unshift(result[0].name);
      console.log(`[\"${name}\", \"${data}\", \"${sig}\"],\n`)
      console.log("\n");
    })
  })






# dnsprove.js 

## Usage

```js
dnsprove = require('dnsprove');
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
}).catch((e)=>{
  console.log('error', e);
})
```

## Testing

Some of js libraries behaved differently depending on the environment you are in. To make sure it runs correctly, run the following commands to make sure it does not raise any errors.

### Truffle

```
truffle test
```

### Node.js

```
node example/main.js
```

### Browser

```
npx browserify  example/main.js -t babelify --outfile example/dist/bundle.js 
open example/index.html
```
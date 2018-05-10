var dns = require("../lib/dns.js");
var dnssec = artifacts.require("./DNSSEC.sol");

const test_rrsets = [
  // .	81356	IN	RRSIG	DNSKEY 8 0 172800 20180522000000 20180501000000 19036 . Mm2wIV8upZjOWo79vGEihnNLCPHTLzO97K4whKutzbCJH0UgcO8w3D8h0zfS/nj6kHtBhUeM9ias+wLRhJsl8D8cok04pJ83e/1Hg5+IS4qY7u08SFf8wuolbLhcX++G8JfOWP4iqwGG01W1HXUlZ65aYiOIAxQcmaj6K8wq/KTK6Vz2ftczpuNi7KkOHphnElBPlyxPW5yKTRzOnDVpmJtdJv2LrzC1aH3pYJIVHHb/C2Wikko5iVZMmF8RDF+TkKJukwurUcpprWOp44PrtcB4CAJXKR1DPJnQ4owEEb2VJWpWM7hN93z+zGNrNbSN9X/q2GVPEjaPmsNbU4yoLg==
  // .	81356	IN	DNSKEY	257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=
  // .	81356	IN	DNSKEY	256 3 8 AwEAAdU4aKlDgEpXWWpH5aXHJZI1Vm9Cm42mGAsqkz3akFctS6zsZHC3pNNMug99fKa7OW+tRHIwZEc//mX8Jt6bcw5bPgRHG6u2eT8vUpbXDPVs1ICGR6FhlwFWEOyxbIIiDfd7Eq6eALk5RNcauyE+/ZP+VdrhWZDeEWZRrPBLjByBWTHl+v/f+xvTJ3Stcq2tEqnzS2CCOr6RTJepprYhu+5Yl6aRZmEVBK27WCW1Zrk1LekJvJXfcyKSKk19C5M5JWX58px6nB1IS0pMs6aCIK2yaQQVNUEg9XyQzBSv/rMxVNNy3VAqOjvh+OASpLMm4GECbSSe8jtjwG0I78sfMZc=
  // .	81356	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
  [".", "003008000002a3005b035d805ae7ae004a5c0000003000010002a30001080100030803010001d53868a943804a57596a47e5a5c7259235566f429b8da6180b2a933dda90572d4bacec6470b7a4d34cba0f7d7ca6bb396fad44723064473ffe65fc26de9b730e5b3e04471babb6793f2f5296d70cf56cd4808647a16197015610ecb16c82220df77b12ae9e00b93944d71abb213efd93fe55dae15990de116651acf04b8c1c815931e5faffdffb1bd32774ad72adad12a9f34b60823abe914c97a9a6b621bbee5897a69166611504adbb5825b566b9352de909bc95df7322922a4d7d0b93392565f9f29c7a9c1d484b4a4cb3a68220adb2690415354120f57c90cc14affeb33154d372dd502a3a3be1f8e012a4b326e061026d249ef23b63c06d08efcb1f319700003000010002a30001080101030803010001a80020a95566ba42e886bb804cda84e47ef56dbd7aec612615552cec906d2116d0ef207028c51554144dfeafe7c7cb8f005dd18234133ac0710a81182ce1fd14ad2283bc83435f9df2f6313251931a176df0da51e54f42e604860dfb359580250f559cc543c4ffd51cbe3de8cfd06719237f9fc47ee729da06835fa452e825e9a18ebc2ecbcf563474652c33cf56a9033bcdf5d973121797ec8089041b6e03a1b72d0a735b984e03687309332324f27c2dba85e9db15e83a0143382e974b0621c18e625ecec907577d9e7bade95241a81ebbe8a901d4d3276e40b114c0a2e6fc38d19c2e6aab02644b2813f575fc21601e0dee49cd9ee96a43103e524d62873d00003000010002a30001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b5", "326db0215f2ea598ce5a8efdbc612286734b08f1d32f33bdecae3084abadcdb0891f452070ef30dc3f21d337d2fe78fa907b4185478cf626acfb02d1849b25f03f1ca24d38a49f377bfd47839f884b8a98eeed3c4857fcc2ea256cb85c5fef86f097ce58fe22ab0186d355b51d752567ae5a62238803141c99a8fa2bcc2afca4cae95cf67ed733a6e362eca90e1e986712504f972c4f5b9c8a4d1cce9c3569989b5d26fd8baf30b5687de96092151c76ff0b65a2924a3989564c985f110c5f9390a26e930bab51ca69ad63a9e383ebb5c078080257291d433c99d0e28c0411bd95256a5633b84df77cfecc636b35b48df57fead8654f12368f9ac35b538ca82e"],

  // xyz.	52014	IN	RRSIG	DS 8 1 86400 20180520170000 20180507160000 39570 . vJdvDZBegpaI31VY+j5VYoGtbRQ+ha/RLd3OVIwNHnjVOprSelYuO4cOedG5bQ5zhaCSJkAmy7hIVs0GP9uNPWVcG4clmBz74aFT5IiWnEM6v4Ot9tJWBKnMjfNMnNsTeChEmRh6H58jO1wIOhttuBfGqHo+oJ3pHAK2wj/ficqAnrQ2TcOoPIWmxflMfrQrvus99/j1kns5eRFTo016jxcqcR/J8KmMdZmQX6vFoZPZtr1dEem/JF/iAsmqVDp3BhnJLURtL3lieE4ympp0PZQcnELe8ywtQsPXFwwuDgFTsflTqURHvAH/xQl49GAZwoROxD4nFpYsFfBmrsZZ8w==
  // xyz.	52014	IN	DS	3599 8 1 3FA3B264F45DB5F38BEDEAF1A88B76AA318C2C7F
  // xyz.	52014	IN	DS	3599 8 2 B9733869BC84C86BB59D102BA5DA6B27B2088552332A39DCD54BC4E8D66B0499
  ["xyz.", "002b0801000151805b01a9905af078009a92000378797a00002b00010001518000180e0f08013fa3b264f45db5f38bedeaf1a88b76aa318c2c7f0378797a00002b00010001518000240e0f0802b9733869bc84c86bb59d102ba5da6b27b2088552332a39dcd54bc4e8d66b0499", "bc976f0d905e829688df5558fa3e556281ad6d143e85afd12dddce548c0d1e78d53a9ad27a562e3b870e79d1b96d0e7385a092264026cbb84856cd063fdb8d3d655c1b8725981cfbe1a153e488969c433abf83adf6d25604a9cc8df34c9cdb1378284499187a1f9f233b5c083a1b6db817c6a87a3ea09de91c02b6c23fdf89ca809eb4364dc3a83c85a6c5f94c7eb42bbeeb3df7f8f5927b39791153a34d7a8f172a711fc9f0a98c7599905fabc5a193d9b6bd5d11e9bf245fe202c9aa543a770619c92d446d2f7962784e329a9a743d941c9c42def32c2d42c3d7170c2e0e0153b1f953a94447bc01ffc50978f46019c2844ec43e2716962c15f066aec659f3"],

  // xyz.	488	IN	RRSIG	DNSKEY 8 1 3600 20180515021130 20180414183948 3599 xyz. OrJosbGfgTU8PMWJHzx89lh5f8eMLTQGjU6GT/oFF1VHf1P4pdD0NbVs6mCyJ3dsD38llNL1eF7/H3Eayo2Fjbiq2n+vvz8/1FKhCM21hvSUVu9Q3DnrDWEbFKeg73j1QK4OOlJU5RKOu/akVGIEt84syc7T6t4ISVoZUIHGQlEsO8ZRI6Z9YmWkf+7oFoiQopSGr3VeOFuVNBsGHyNdl7/hAcrUEMhXaqCoHagNwBDycxhbuSYxwn5FaODXlwIgx7QinNRGrEBjpKC5RxVTZ3IgTTTWUzolc1rFbJincNaDkf3ng6oSpn0nRSyf32cSyl/kPlyt+11cayDvAoKGQA==
  // xyz.	488	IN	DNSKEY	257 3 8 AwEAAbYRTzkgLg4oxcFb/+oFQMvluEut45siTtLiNL7t5Fim/ZnYhkxal6TiCUywnfgiycJyneNmtC/3eoTcz5dlrlRB5dwDehcqiZoFiqjaXGHcykHGFBDynD0/sRcEAQL+bLMv2qA+o2L7pDPHbCGJVXlUq57oTWfS4esbGDIa+1Bs8gDVMGUZcbRmeeKkc/MH2Oq1ApE5EKjH0ZRvYWS6afsWyvlXD2NXDthS5LltVKqqjhi6dy2O02stOt41z1qwfRlU89b3HXfDghlJ/L33DE+OcTyK0yRJ+ay4WpBgQJL8GDFKz1hnR2lOjYXLttJD7aHfcYyVO6zYsx2aeHI0OYM=
  // xyz.	488	IN	DNSKEY	256 3 8 AwEAAa6CLBIa4fmw7gt9YTsutscEOLeGjGnu+w2C+yLpQqvuZNu9O2BdVNjv0VwoP0fc33eYUh3OLgwki8O3ZjfneQPKmYJLkbLmWvRrX+mV8zUGGF3qOgOYk34ewK8fhHZO07UY7xk4jKjiCa+52OSdyof6tR3My+QOjQZH3mn9b/GX
  // xyz.	488	IN	DNSKEY	256 3 8 AwEAAYNktvUuoOalRZ7fB2EGfUkqOqIVNZcx9YaU3i8CubvOetVo8n+oUvvivq8+Vs2XithtiMzExJPGtJOjk38hibkBfCFcjNdiMQpce+ZfpJtRcmB30R+hxpHXiRwS7y6pPT3g2/dyeQJckH7R1qR6TQgqqVi/Mgbs6FmvpxgI9Dy7
  ["xyz.", "0030080100000e105afa41d25ad24af40e0f0378797a000378797a000030000100000e10008801000308030100018364b6f52ea0e6a5459edf0761067d492a3aa215359731f58694de2f02b9bbce7ad568f27fa852fbe2beaf3e56cd978ad86d88ccc4c493c6b493a3937f2189b9017c215c8cd762310a5c7be65fa49b51726077d11fa1c691d7891c12ef2ea93d3de0dbf77279025c907ed1d6a47a4d082aa958bf3206ece859afa71808f43cbb0378797a000030000100000e1000880100030803010001ae822c121ae1f9b0ee0b7d613b2eb6c70438b7868c69eefb0d82fb22e942abee64dbbd3b605d54d8efd15c283f47dcdf7798521dce2e0c248bc3b76637e77903ca99824b91b2e65af46b5fe995f33506185dea3a0398937e1ec0af1f84764ed3b518ef19388ca8e209afb9d8e49dca87fab51dcccbe40e8d0647de69fd6ff1970378797a000030000100000e1001080101030803010001b6114f39202e0e28c5c15bffea0540cbe5b84bade39b224ed2e234beede458a6fd99d8864c5a97a4e2094cb09df822c9c2729de366b42ff77a84dccf9765ae5441e5dc037a172a899a058aa8da5c61dcca41c61410f29c3d3fb117040102fe6cb32fdaa03ea362fba433c76c2189557954ab9ee84d67d2e1eb1b18321afb506cf200d530651971b46679e2a473f307d8eab502913910a8c7d1946f6164ba69fb16caf9570f63570ed852e4b96d54aaaa8e18ba772d8ed36b2d3ade35cf5ab07d1954f3d6f71d77c3821949fcbdf70c4f8e713c8ad32449f9acb85a90604092fc18314acf586747694e8d85cbb6d243eda1df718c953bacd8b31d9a7872343983", "3ab268b1b19f81353c3cc5891f3c7cf658797fc78c2d34068d4e864ffa051755477f53f8a5d0f435b56cea60b227776c0f7f2594d2f5785eff1f711aca8d858db8aada7fafbf3f3fd452a108cdb586f49456ef50dc39eb0d611b14a7a0ef78f540ae0e3a5254e5128ebbf6a4546204b7ce2cc9ced3eade08495a195081c642512c3bc65123a67d6265a47feee8168890a29486af755e385b95341b061f235d97bfe101cad410c8576aa0a81da80dc010f273185bb92631c27e4568e0d7970220c7b4229cd446ac4063a4a0b94715536772204d34d6533a25735ac56c98a770d68391fde783aa12a67d27452c9fdf6712ca5fe43e5cadfb5d5c6b20ef02828640"],

  // ethlab.xyz.	3599	IN	RRSIG	DS 8 2 3600 20180603040300 20180504054358 48429 xyz. XCf5FksrqPEwuRJT/mSQutDUCrxycTw6tMvEDHfgcRAS2IGP74HjSpb4zOiyHeA8Wly3PXX+/5OYcdrhNZMXfk06ZzDdJ8nB/vCZDdx9Q9f1N3UYjGiqXRmzHiTbOjdpSmiQcnW3OW1hqVmZJCKp9lzHHuyglwLBXx/RWeJKaN8=
  // ethlab.xyz.	3599	IN	DS	60820 8 2 D1CDCF8E905ED06FEC438A63C69A34D2F4871B1F4869BBB852859892E693CAED
  // ethlab.xyz.	3599	IN	DS	42999 8 2 954C021A38E5731EBAAA95323FB7C472A866CE4D86AE3AD8605843B722B62213
  ["ethlab.xyz.", "002b080200000e105b1368745aebf31ebd2d0378797a00066574686c61620378797a00002b000100000e100024a7f70802954c021a38e5731ebaaa95323fb7c472a866ce4d86ae3ad8605843b722b62213066574686c61620378797a00002b000100000e100024ed940802d1cdcf8e905ed06fec438a63c69a34d2f4871b1f4869bbb852859892e693caed", "5c27f9164b2ba8f130b91253fe6490bad0d40abc72713c3ab4cbc40c77e0711012d8818fef81e34a96f8cce8b21de03c5a5cb73d75feff939871dae13593177e4d3a6730dd27c9c1fef0990ddc7d43d7f53775188c68aa5d19b31e24db3a37694a68907275b7396d61a959992422a9f65cc71eeca09702c15f1fd159e24a68df"],

  // ethlab.xyz.	299	IN	RRSIG	DNSKEY 8 2 300 20320927145531 20171016135531 42999 ethlab.xyz. kCWUTbG6licygmytAdeH9dKc5EsNmGwUImTQlqjIlKJLt9nwPO2ncIW5AllRRU2hpKKFDuZdUC5z6uV0Jsr74g==
  // ethlab.xyz.	299	IN	DNSKEY	257 3 8 AwEAAbjW5+pT9WirUzRujl+Haab7lw8NOa7N1FdRjpJ4ICzvOfc1vSYULj2eBIQJq5lys1Bhgs0NXHGsR0UDVok+uu7dic+UlEH8gIAa82yPefJOotD6yCZfqk1cuLX2+RGMHfpVgs4qwQa+PdajYfpw+sjzafGBuwiygycuZe40p4/Azm3E5/9lFsis4z3bXOd5vTdKYv5AWdEgKRdzZIRjIxurKz6G7nXPaxOn4zo4LM/kXxn4KjSLQQxQflr+xxHxda8zJZOY1Pj3iKcMzPtPHUsxbHbcjszmwNrn7sqNpSEPsoAw4+UQCG0FnhwsQxnAo5rE2YxJV1S+BRcAunyEsUE=
  // ethlab.xyz.	299	IN	DNSKEY	256 3 8 AwEAAdlnRTgge2TmnkenqHAh6YXRNWobwj0r23zHhgLxkN3IB7iAyUulB1L92aS60hHbfYJ1aXjFnF1fhXvAxaAgQN0=
  ["ethlab.xyz.", "003008020000012c7603066359e4ba53a7f7066574686c61620378797a00066574686c61620378797a00003000010000012c00480100030803010001d9674538207b64e69e47a7a87021e985d1356a1bc23d2bdb7cc78602f190ddc807b880c94ba50752fdd9a4bad211db7d82756978c59c5d5f857bc0c5a02040dd066574686c61620378797a00003000010000012c01080101030803010001b8d6e7ea53f568ab53346e8e5f8769a6fb970f0d39aecdd457518e9278202cef39f735bd26142e3d9e048409ab9972b3506182cd0d5c71ac47450356893ebaeedd89cf949441fc80801af36c8f79f24ea2d0fac8265faa4d5cb8b5f6f9118c1dfa5582ce2ac106be3dd6a361fa70fac8f369f181bb08b283272e65ee34a78fc0ce6dc4e7ff6516c8ace33ddb5ce779bd374a62fe4059d120291773648463231bab2b3e86ee75cf6b13a7e33a382ccfe45f19f82a348b410c507e5afec711f175af33259398d4f8f788a70cccfb4f1d4b316c76dc8ecce6c0dae7eeca8da5210fb28030e3e510086d059e1c2c4319c0a39ac4d98c495754be051700ba7c84b141", "9025944db1ba962732826cad01d787f5d29ce44b0d986c142264d096a8c894a24bb7d9f03ceda77085b9025951454da1a4a2850ee65d502e73eae57426cafbe2"],

  // _ens.ethlab.xyz.	21599	IN	RRSIG	TXT 8 3 86400 20320926152530 20171015142530 42999 ethlab.xyz. FhBZI7LarPHOX/1cjiWpX0IFisWAgIao4VEPeqgoYJVkqF6lv7KlaZcAp2n9AEHk1ynffrxoVbijdCUoDn6q8A==
  // _ens.ethlab.xyz.	21599	IN	TXT	"a=0xfdb33f8ac7ce72d7d4795dd8610e323b4c122fbb"
  ["_ens.ethlab.xyz.", "00100803000151807601bbea59e36fdaa7f7066574686c61620378797a00045f656e73066574686c61620378797a000010000100015180002d2c613d307866646233336638616337636537326437643437393564643836313065333233623463313232666262", "16105923b2daacf1ce5ffd5c8e25a95f42058ac5808086a8e1510f7aa828609564a85ea5bfb2a5699700a769fd0041e4d729df7ebc6855b8a37425280e7eaaf0"]
];

async function verifySubmission(instance, name, data, sig, proof) {
  if(proof === undefined) {
    proof = await instance.anchors();
  }

  var name = dns.hexEncodeName(name);
  var tx = await instance.submitRRSet(name, data, sig, proof);
  assert.equal(parseInt(tx.receipt.status), parseInt('0x1'));
  assert.equal(tx.logs.length, 1);
  assert.equal(tx.logs[0].args.name, name);
  return tx;
}

async function verifyFailedSubmission(instance, name, data, sig, proof) {
  if(proof === undefined) {
    proof = await instance.anchors();
  }

  var name = dns.hexEncodeName(name);
  try{
    var tx = await instance.submitRRSet(name, data, sig, proof);
  }
  catch(error){
    // Assert ganache revert exception
    assert.equal(error.message, 'VM Exception while processing transaction: revert');
  }
  // Assert geth failed transaction
  if(tx !== undefined) {
    assert.equal(parseInt(tx.receipt.status), parseInt('0x0'));
  }
}

contract('DNSSEC', function(accounts) {
  it('should have a default algorithm and digest set', async function() {
    var instance = await dnssec.deployed();
    assert.notEqual(await instance.algorithms(8), "0x0000000000000000000000000000000000000000");
    assert.notEqual(await instance.algorithms(253), "0x0000000000000000000000000000000000000000");
    assert.notEqual(await instance.digests(2), "0x0000000000000000000000000000000000000000");
    assert.notEqual(await instance.digests(253), "0x0000000000000000000000000000000000000000");
  });

  function rootKeys() {
    return {
      typeCovered: dns.TYPE_DNSKEY,
      algorithm: 253,
      labels: 0,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 0,
      keytag: 5647,
      signerName: ".",
      rrs: [
        {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 253, pubkey: new Buffer("1111", "HEX")},
        {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0, protocol: 4, algorithm: 253, pubkey: new Buffer("1111", "HEX")},
        {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0, protocol: 3, algorithm: 253, pubkey: new Buffer("1112", "HEX")}
      ],
    };
  };

  it("should reject signatures with non-matching algorithms", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs = [
      {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 254, pubkey: new Buffer("1111", "HEX")}
    ];
    await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should reject signatures with non-matching keytags", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs = [
      {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 253, pubkey: new Buffer("1112", "HEX")}
    ];
    await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should reject signatures by keys without the ZK bit set", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs = [
      {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0001, protocol: 3, algorithm: 253, pubkey: new Buffer("1211", "HEX")}
    ];
    await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  var rootKeyProof = undefined;
  it('should accept a root DNSKEY', async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    var tx = await verifySubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
    rootKeyProof = tx.logs[0].args.rrset;
  });

  it('should check if root DNSKEY exist', async function(){
    var instance = await dnssec.deployed();
    var [_, _, rrs] = await instance.rrdata.call(dns.TYPE_DNSKEY, dns.hexEncodeName('nonexisting.'));
    assert.equal(rrs, '0x0000000000000000000000000000000000000000');
    [_, _, rrs] = await instance.rrdata.call(dns.TYPE_DNSKEY, dns.hexEncodeName('.'));
    assert.notEqual(rrs, '0x0000000000000000000000000000000000000000');
  })

  it('should accept a signed RRSET', async function() {
    var instance = await dnssec.deployed();
    var proof = dns.hexEncodeRRs(rootKeys().rrs);
    await verifySubmission(instance, "test.", dns.hexEncodeSignedSet({
      typeCovered: dns.TYPE_TXT,
      algorithm: 253,
      labels: 1,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 1,
      keytag: 5647,
      signerName: ".",
      rrs: [
        {name: "test.", type: dns.TYPE_TXT, klass: 1, ttl: 3600, text: ["test"]}
      ],
    }), "0x", proof);
  });

  it('should reject signatures with non-matching classes', async function() {
    var instance = await dnssec.deployed();
    await verifyFailedSubmission(instance, "net.", dns.hexEncodeSignedSet({
      typeCovered: dns.TYPE_TXT,
      algorithm: 253,
      labels: 1,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 0,
      keytag: 5647,
      signerName: ".",
      rrs: [
        {name: "net.", type: dns.TYPE_TXT, klass: 2, ttl: 3600, text: ["foo"]}
      ],
    }), "0x");
  })

  it('should reject signatures with non-matching names', async function() {
    var instance = await dnssec.deployed();
    await verifyFailedSubmission(instance, "net.", dns.hexEncodeSignedSet({
      typeCovered: dns.TYPE_TXT,
      algorithm: 253,
      labels: 1,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 0,
      keytag: 5647,
      signerName: ".",
      rrs: [
        {name: "foo.net.", type: dns.TYPE_TXT, klass: 1, ttl: 3600, text: ["foo"]}
      ],
    }), "0x");
  });

  it('should reject signatures with the wrong type covered', async function() {
    var instance = await dnssec.deployed();
    await verifyFailedSubmission(instance, "net.", dns.hexEncodeSignedSet({
      typeCovered: dns.TYPE_DS,
      algorithm: 253,
      labels: 1,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 0,
      keytag: 5647,
      signerName: ".",
      rrs: [
        {name: "net.", type: dns.TYPE_TXT, klass: 1, ttl: 3600, text: ["foo"]}
      ],
    }), "0x");
  });

  it('should reject signatures with too many labels', async function() {
    var instance = await dnssec.deployed();
    await verifyFailedSubmission(instance, "net.", dns.hexEncodeSignedSet({
      typeCovered: dns.TYPE_TXT,
      algorithm: 253,
      labels: 2,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 0,
      keytag: 5647,
      signerName: ".",
      rrs: [
        {name: "net.", type: dns.TYPE_TXT, klass: 1, ttl: 3600, text: ["foo"]}
      ],
    }), "0x");
  });

  it('should support wildcard subdomains', async function() {
    var instance = await dnssec.deployed();
    var proof = dns.hexEncodeRRs(rootKeys().rrs);
    await verifySubmission(instance, "foo.net.", dns.hexEncodeSignedSet({
      typeCovered: dns.TYPE_TXT,
      algorithm: 253,
      labels: 1,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 1,
      keytag: 5647,
      signerName: ".",
      rrs: [
        {name: "*.net.", type: dns.TYPE_TXT, klass: 1, ttl: 3600, text: ["foo"]}
      ],
    }), "0x", proof);
  });

  it('should reject signatures with invalid signer names', async function() {
    var instance = await dnssec.deployed();

    await verifySubmission(instance, "net.", dns.hexEncodeSignedSet({
      typeCovered: dns.TYPE_DNSKEY,
      algorithm: 253,
      labels: 1,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 0,
      keytag: 5647,
      signerName: ".",
      rrs: [
        {name: "net.", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 253, pubkey: new Buffer("1111", "HEX")}
      ]
    }), "0x");

    await verifyFailedSubmission(instance, "com.", dns.hexEncodeSignedSet({
      typeCovered: dns.TYPE_TXT,
      algorithm: 253,
      labels: 1,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 0,
      keytag: 5647,
      signerName: "net.",
      rrs: [
        {name: "com.", type: dns.TYPE_TXT, klass: 1, ttl: 3600, text: ["foo"]}
      ],
    }), "0x");
  });

  it("should reject entries with expirations in the past", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.inception = 1;
    keys.expiration = 123;
    await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should reject entries with inceptions in the future", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.inception = 0xFFFFFFFF;
    await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should accept updates with newer signatures", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.inception = 1;
    await verifySubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should reject entries that are older", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.inception = 0;
    await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it('should reject invalid RSA signatures', async function() {
    var instance = await dnssec.deployed();
    var sig = test_rrsets[0][2];
    await verifyFailedSubmission(instance, test_rrsets[0][0], "0x" + test_rrsets[0][1], "0x" + sig.slice(0, sig.length - 2) + "FF");
  });

  // Test delete RRSET
  async function checkPresence(instance, type, name){
    var result = (await instance.rrdata.call(type, dns.hexEncodeName(name)))[2];
    return result != '0x0000000000000000000000000000000000000000';
  }

  async function submitEntry(instance, type, name, option, proof){
    var rrs = {name: name, type: type, klass: 1, ttl: 3600};
    Object.assign(rrs, option)
    var keys = {
      typeCovered: type,
      algorithm: 253,
      labels: 1,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 1,
      keytag: 5647,
      signerName: ".",
      rrs: [rrs],
    };
    var [inception, _, rrs] = await instance.rrdata.call(type, dns.hexEncodeName(name));
    if(rrs != '0x0000000000000000000000000000000000000000'){
      keys.inception = inception + 1;
    };
    tx = await verifySubmission(instance, name, dns.hexEncodeSignedSet(keys), "0x", proof);
    [_, _, rrs] = await instance.rrdata.call(type, dns.hexEncodeName(name));
    assert.notEqual(rrs, '0x0000000000000000000000000000000000000000');
    return tx;
  }

  async function deleteEntry(instance, deletetype, deletename, ensname, proof) {
    var tx, result;
    try{
      tx = await instance.deleteRRSet(deletetype, dns.hexEncodeName(deletename), dns.hexEncodeName(ensname), proof);
    }
    catch(error){
      // Assert ganache revert exception
      assert.equal(error.message, 'VM Exception while processing transaction: revert');
      result = false;
    }
    // Assert geth failed transaction
    if(tx !== undefined) {
      result = (parseInt(tx.receipt.status) == parseInt('0x1'));
    }
    return result;
  }

  it('rejects if NSEC record is not found', async function(){
    var instance = await dnssec.deployed();
    await submitEntry(instance, dns.TYPE_TXT, 'b.', {text: ["foo"]}, rootKeyProof);
    // Submit with a proof for an irrelevant record.
    assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'b.', 'a.', rootKeyProof)), false);
    assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'b.')), true);
  })

  it('rejects if next record does not come before the deleting name', async function(){
    var instance = await dnssec.deployed();
    // text z. comes after next d.
    await submitEntry(instance, dns.TYPE_TXT, 'z.', {text: ["foo"]}, rootKeyProof);
    var tx = await submitEntry(instance, dns.TYPE_NSEC, 'a.', {next:'d.', rrtypes:[dns.TYPE_TXT]}, rootKeyProof);
    assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'z.', 'a.', tx.logs[0].args.rrset)), false);
    assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'z.')), true);
  })

  it('rejects if nsec record starts after the deleting name', async function(){
    var instance = await dnssec.deployed();
    // text a. comes after nsec b.
    await submitEntry(instance, dns.TYPE_TXT, 'a.', {text: ["foo"]}, rootKeyProof);
    var tx = await submitEntry(instance, dns.TYPE_NSEC, 'b.', {next:'d.', rrtypes:[dns.TYPE_TXT]}, rootKeyProof);
    assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'a.', 'b.', tx.logs[0].args.rrset)), false);
    assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'a.')), true);
  })

  it('rejects RRset if trying to delete rrset that is in the type bitmap', async function(){
    var instance = await dnssec.deployed();
    // text a. has same nsec a. with type bitmap
    await submitEntry(instance, dns.TYPE_TXT, 'a.', { text:['foo']}, rootKeyProof);
    var tx = await submitEntry(instance, dns.TYPE_NSEC, 'a.', { next:'d.', rrtypes:[dns.TYPE_TXT] }, rootKeyProof);
    assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'a.', 'a.', tx.logs[0].args.rrset)), false);
    assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'a.')), true);
  })

  it('deletes RRset if nsec name and delete name are the same but with different rrtypes', async function(){
    var instance = await dnssec.deployed();
    await submitEntry(instance, dns.TYPE_TXT,  'a.', { text: ["foo"] }, rootKeyProof);
    // This test fails if rrtypes is empty ([]), but would that case every happen?
    var tx = await submitEntry(instance, dns.TYPE_NSEC, 'a.', { next:'d.', rrtypes:[dns.TYPE_NSEC] }, rootKeyProof);
    assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'a.', 'a.', tx.logs[0].args.rrset)), true);
    assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'a.')), false);
  })

  it('deletes RRset if NSEC next comes after delete name', async function(){
    var instance = await dnssec.deployed();
    await submitEntry(instance, dns.TYPE_TXT, 'b.', {text: ["foo"]}, rootKeyProof);
    var tx = await submitEntry(instance, dns.TYPE_NSEC, 'a.', { next:'d.', rrtypes:[dns.TYPE_TXT] }, rootKeyProof);
    assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'b.', 'a.', tx.logs[0].args.rrset)), true);
    assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'b.')), false);
  })

  // Test against real record
  it('should accept real DNSSEC records', async function() {
    var instance = await dnssec.deployed();
    var proof = await instance.anchors();
    for(var rrset of test_rrsets) {
      console.log(rrset[0]);
      var tx = await verifySubmission(instance, rrset[0], "0x" + rrset[1], "0x" + rrset[2], proof);
      assert.equal(tx.logs.length, 1);
      assert.equal(tx.logs[0].event, 'RRSetUpdated');
      proof = tx.logs[0].args.rrset;
    }
  });
});

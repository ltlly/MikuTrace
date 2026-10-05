// 单字段差分：除目标字段外 12 个参数完全固定，逐个字段变化，定位 x-sign 的依赖字节区间
// INPUT 由主机侧预算好传入（field -> 完整 INPUT）
var INPUTS = {"base": "&&&34394984&ea3101dbf29d618e5f636e9e583bd9ea&1791180000000&mtop.intf.signedTest&1.0&&&&&&&&&&&&&&&&", "rid": "&&&34394984&ea3101dbf29d618e5f636e9e583bd9ea&1791180000000&mtop.intf.signedTest&1.0&&&&&&&&&&&&&&&&", "api2": "&&&34394984&ea3101dbf29d618e5f636e9e583bd9ea&1791180000000&mtop.intf.other&1.0&&&&&&&&&&&&&&&&", "api3": "&&&34394984&ea3101dbf29d618e5f636e9e583bd9ea&1791180000000&mtop.taobao.detail.getdetail&1.0&&&&&&&&&&&&&&&&", "t2": "&&&34394984&ea3101dbf29d618e5f636e9e583bd9ea&1791180000001&mtop.intf.signedTest&1.0&&&&&&&&&&&&&&&&", "data2": "&&&34394984&b2f1fa5a652f04607c6737c26df1db50&1791180000000&mtop.intf.signedTest&1.0&&&&&&&&&&&&&&&&", "v2": "&&&34394984&ea3101dbf29d618e5f636e9e583bd9ea&1791180000000&mtop.intf.signedTest&2.0&&&&&&&&&&&&&&&&", "utdid": "ZTAxMjM0NTY3ODk=&&&34394984&ea3101dbf29d618e5f636e9e583bd9ea&1791180000000&mtop.intf.signedTest&1.0&&&&&&&&&&&&&&&&", "uid": "&10086&&34394984&ea3101dbf29d618e5f636e9e583bd9ea&1791180000000&mtop.intf.signedTest&1.0&&&&&&&&&&&&&&&&", "sid": "&&&34394984&ea3101dbf29d618e5f636e9e583bd9ea&1791180000000&mtop.intf.signedTest&1.0&sess-1&&&&&&&&&&&&&&&", "ttid": "&&&34394984&ea3101dbf29d618e5f636e9e583bd9ea&1791180000000&mtop.intf.signedTest&1.0&&ttid-1&&&&&&&&&&&&&&", "dev": "&&&34394984&ea3101dbf29d618e5f636e9e583bd9ea&1791180000000&mtop.intf.signedTest&1.0&&&dev-1&&&&&&&&&&&&&", "xf": "&&&34394984&ea3101dbf29d618e5f636e9e583bd9ea&1791180000000&mtop.intf.signedTest&1.0&&&&&&&27&&&&&&&&&", "ed": "&&&34394984&ea3101dbf29d618e5f636e9e583bd9ea&1791180000000&mtop.intf.signedTest&1.0&&&&&&ed-1&&&&&&&&&&", "appkey2": "&&&12574478&ea3101dbf29d618e5f636e9e583bd9ea&1791180000000&mtop.intf.signedTest&1.0&&&&&&&&&&&&&&&&", "empty": "&&&34394984&d41d8cd98f00b204e9800998ecf8427e&1791180000000&mtop.intf.signedTest&1.0&&&&&&&&&&&&&&&&", "data1": "&&&34394984&0cc175b9c0f1b6a831c399e269772661&1791180000000&mtop.intf.signedTest&1.0&&&&&&&&&&&&&&&&"};
var FIELDS = [{"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "reps": 1, "tag": "same0", "input": "base"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "reps": 1, "tag": "same1", "input": "base"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "reps": 1, "tag": "same2", "input": "base"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "reps": 1, "tag": "same3", "input": "base"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "reps": 1, "tag": "same4", "input": "base"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "reps": 1, "tag": "same5", "input": "base"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "other-req-id", "bizId": 0, "flag": 0, "tag": "rid2", "input": "base"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "api2", "input": "api2"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "api3", "input": "api3"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "t2", "input": "t2"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "data2", "input": "data2"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "v2", "input": "v2"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "utdid", "input": "utdid"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "uid", "input": "uid"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "sid", "input": "sid"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "ttid", "input": "ttid"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "dev", "input": "dev"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "xf", "input": "xf"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "ed", "input": "ed"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "empty", "input": "empty"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "data1", "input": "data1"}, {"useWua": false, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "useWuaF", "input": "base"}, {"useWua": true, "env": 1, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "env1", "input": "base"}, {"useWua": true, "env": 2, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "env2", "input": "base"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "x-features=99", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "extp", "input": "base"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 7, "flag": 0, "tag": "biz7", "input": "base"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 9, "tag": "flag9", "input": "base"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": "ZZZ", "signKey": null, "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "authC", "input": "base"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": "SKK", "miniWua": null, "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "signK", "input": "base"}, {"useWua": true, "env": 0, "api": "mtop.intf.signedTest", "ext": "", "authCode": null, "signKey": null, "miniWua": "MWW", "rid": "fixed-req-id-0001", "bizId": 0, "flag": 0, "tag": "miniW", "input": "base"}];

function s(v) { try { var x = String(v); return x.length > 160 ? x.slice(0, 160) + '...' : x; } catch (e) { return '<?>'; } }

Java.perform(function () {
  var loaders = Java.enumerateClassLoadersSync ? Java.enumerateClassLoadersSync() : [];
  var loader = null;
  for (var li = 0; li < loaders.length && loader === null; li++) {
    var ld = loaders[li];
    var d = '';
    try { d = String(ld); } catch (e) {}
    if (d.indexOf('libsgmain.so') < 0) continue;
    try { Java.ClassFactory.get(ld).use('com.taobao.wireless.security.adapter.JNICLibrary'); loader = ld; } catch (e) {}
  }
  console.log('pluginLoader=' + (loader !== null));
  if (loader === null) { console.log('no plugin loader'); return; }
  var J = Java.ClassFactory.get(loader).use('com.taobao.wireless.security.adapter.JNICLibrary');
  var Integer = Java.use('java.lang.Integer');
  var Boolean = Java.use('java.lang.Boolean');

  var REQID = 'fixed-req-id-0001';
  var API = 'mtop.intf.signedTest';

  function run(tag, input, useWua, env, api, ext, authCode, signKey, miniWua, rid, bizId, flag) {
    var raw = ['34394984', input, Boolean.valueOf(useWua), Integer.valueOf(env), api, ext,
               authCode, signKey, miniWua, rid, Integer.valueOf(bizId), Integer.valueOf(flag)];
    var args = Java.array('java.lang.Object', raw);
    try {
      var r = J.doCommandNative(70102, args);
      var HM = Java.cast(r, Java.use('java.util.Map'));
      console.log('JSON ' + JSON.stringify({
        tag: tag, input: input, useWua: useWua, env: env, api: api, ext: ext, rid: rid, bizId: bizId, flag: flag,
        sign: HM.get('x-sign') === null ? null : String(HM.get('x-sign')),
        umt: HM.get('x-umt') === null ? null : String(HM.get('x-umt'))
      }));
    } catch (e) { console.log('JSON ' + JSON.stringify({ tag: tag, error: String(e) })); }
  }

  var k = 0;
  function step() {
    if (k >= FIELDS.length) { console.log('ALLDONE'); return; }
    var f = FIELDS[k++];
    if (f.reps) {
      for (var r2 = 0; r2 < f.reps; r2++) {
        run(f.tag + (f.reps > 1 ? '#' + r2 : ''), INPUTS[f.input], f.useWua, f.env, f.api, f.ext,
            f.authCode, f.signKey, f.miniWua, f.rid, f.bizId, f.flag);
      }
    } else {
      run(f.tag, INPUTS[f.input], f.useWua, f.env, f.api, f.ext, f.authCode, f.signKey, f.miniWua, f.rid, f.bizId, f.flag);
    }
    setTimeout(step, 0);
  }
  setTimeout(step, 0);
});

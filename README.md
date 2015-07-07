## node eait-kvd

Client for the EAIT KVD protocol in node.js.

```shell
npm install eait-kvd
```

```javascript
var kvd = require('eait-kvd');
var c = new kvd.Client('glucose');

var blob = {foo: "bar", created_by: "test"};
c.create(blob, function(err, key) {
    if (err)
        return console.log("create failed: " + err);

    console.log("wrote key '" + key + "'");

    c.get(key, function(err, val) {
        if (err)
            return console.log("get failed: " + err);

        console.log("read key: ", val);
    });
});
```

// Copyright IBM Corp. 2014,2016. All Rights Reserved.
// Node module: loopback
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

var path = require('path');
var jwtRest = require('../middleware/jwt-rest');

describe('loopback.rest', function() {
  this.timeout(10000);
  var app, MyModel;

  beforeEach(function() {
    // override the global app object provided by test/support.js
    // and create a local one that does not share state with other tests
    app = loopback({ localRegistry: true, loadBuiltinModels: true });
    app.set('remoting', { errorHandler: { debug: true, log: false }});
    var db = app.dataSource('db', { connector: 'memory' });
    MyModel = app.registry.createModel('MyModel');
    MyModel.attachTo(db);
  });

  it('bad token', function(done) {
    app.model(MyModel);
    app.enableAuth({ dataSource: 'db' });
    app.use(jwtRest({secret: 'ningmengbao'}));
    supertest(app).get('/mymodels')
      .set('Authorization', 'xxx')
      .expect(401, done);
  });

  it('correct token', function(done) {
    app.model(MyModel);
    app.enableAuth({ dataSource: 'db' });
    app.use(jwtRest({secret: 'ningmengbao'}));
    supertest(app).get('/mymodels')
      .set('Authorization', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOiI1N2NhN2I3MGMwN2FmYjRiMmI3OWYzMGIiLCJ0dGwiOjEyMDk2MDAsInR5cGUiOjEsImtleSI6IjZkYzAzNDFjZjQ1NDk5ZGVlZTlhYTVkYmE3ZDNmNWZjIn0.CLWHGEgYjiNbiL1OJZc0lu8znVaNMzkldU_xpteS8pg')
      .expect(200, done);
  });

  it('token with wrong secret', function(done) {
    app.model(MyModel);
    app.enableAuth({ dataSource: 'db' });
    app.use(jwtRest({secret: 'ningmengbao'}));
    supertest(app).get('/mymodels')
      .set('Authorization', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE0NzMyNDAyOTIsImV4cCI6MTUwNDc3NjI5MiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.6-ay8pEuU70OVXGn-eUPcFHfB_FiBz_AzO_IS-fTxz4')
      .expect(401, done);
  });
});
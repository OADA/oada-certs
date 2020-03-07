const jose = require('node-jose');
const uuid = require('uuid/v4');

async function createKey() {
  const k = await jose.JWK.createKey('RSA', 2048, { kid: uuid().replace(/-/g,'') }); // assign a random string ID (I don't like the dashes in uuids)
  return {
    public: k.toJSON(),
    private: k.toJSON(true),
  };
}

module.exports = createKey;

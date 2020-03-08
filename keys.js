const jose = require('node-jose');
const uuid = require('uuid/v4');

async function create() {
  const k = await jose.JWK.createKey('RSA', 2048, { kid: uuid().replace(/-/g,'') }); // assign a random string ID (I don't like the dashes in uuids)
  return {
    public: k.toJSON(),
    private: k.toJSON(true),
  };
}

async function pubFromPriv(privJWK) {
  const k = await jose.JWK.asKey(privJWK);
  return k.toJSON(); // if you don't pass true to this function, you get back just the public key
}

module.exports = {
  create,
  pubFromPriv,
};

// There are many reasons why the format may be invalid, pass all errors on 
// 'errors' array attached to the Error
module.exports = {
  InvalidFormatException: function InvalidFormatException(message, errors) {
    this.message = message;
    this.name = 'Invalid Format Exception';
    this.errors = errors;
    this.stack = (new Error()).stack;
  },

  InvalidKeyException: function InvalidKeyException(message) {
    this.message = message;
    this.name = 'Invalid Key Exception';
    this.stack = (new Error()).stack;
  },

  SignatureFailedException: function SignatureFailedException(message, errors) {
    this.message = message;
    this.name = 'Signature Failed Exception';
    this.errors = errors;
    this.stack = (new Error()).stack;
  }
}

var assert = require('assert');
var maci_crypto_1 = require('maci-crypto');
var Keypair = (function () {
    function Keypair(privKey) {
        if (privKey) {
            this.privKey = privKey;
            this.pubKey = new PubKey(maci_crypto_1.genPubKey(privKey.rawPrivKey));
        }
        else {
            var rawKeyPair = maci_crypto_1.genKeypair();
            this.privKey = new PrivKey(rawKeyPair.privKey);
            this.pubKey = new PubKey(rawKeyPair.pubKey);
        }
    }
    Keypair.genEcdhSharedKey = function (privKey, pubKey) {
        return maci_crypto_1.genEcdhSharedKey(privKey.rawPrivKey, pubKey.rawPubKey);
    };
    Keypair.prototype.equals = function (keypair) {
        var equalPrivKey = this.privKey.rawPrivKey === keypair.privKey.rawPrivKey;
        var equalPubKey = this.pubKey.rawPubKey[0] === keypair.pubKey.rawPubKey[0] &&
            this.pubKey.rawPubKey[1] === keypair.pubKey.rawPubKey[1];
        // If this assertion fails, something is very wrong and this function
        // should not return anything 
        // XOR is equivalent to: (x && !y) || (!x && y ) 
        var x = (equalPrivKey && equalPubKey);
        var y = (!equalPrivKey && !equalPubKey);
        assert((x && !y) || (!x && y));
        return equalPrivKey;
    };
    return Keypair;
})();
exports.Keypair = Keypair;
var PrivKey = (function () {
    function PrivKey(rawPrivKey) {
        var _this = this;
        this.asCircuitInputs = function () {
            return maci_crypto_1.formatPrivKeyForBabyJub(_this.rawPrivKey).toString();
        };
        this.rawPrivKey = rawPrivKey;
    }
    return PrivKey;
})();
exports.PrivKey = PrivKey;
var PubKey = (function () {
    function PubKey(rawPubKey) {
        var _this = this;
        this.asContractParam = function () {
            return {
                x: _this.rawPubKey[0].toString(),
                y: _this.rawPubKey[1].toString()
            };
        };
        this.asCircuitInputs = function () {
            return _this.rawPubKey.map(function (x) { return x.toString(); });
        };
        this.asArray = function () {
            return [
                _this.rawPubKey[0],
                _this.rawPubKey[1],
            ];
        };
        this.rawPubKey = rawPubKey;
    }
    return PubKey;
})();
exports.PubKey = PubKey;
/*
 * An encrypted command and signature.
 */
var Message = (function () {
    function Message(iv, data) {
        var _this = this;
        this.asArray = function () {
            return [
                _this.iv
            ].concat(_this.data);
        };
        this.asContractParam = function () {
            return {
                iv: _this.iv.toString(),
                data: _this.data.map(function (x) { return x.toString(); })
            };
        };
        this.asCircuitInputs = function () {
            return _this.asArray();
        };
        this.hash = function () {
            return maci_crypto_1.hash(_this.asArray());
        };
        // TODO: add an assert on the length of data
        assert(data.length === 10);
        this.iv = iv;
        this.data = data;
    }
    return Message;
})();
exports.Message = Message;
/*
 * A leaf in the state tree, which maps public keys to votes
 */
var StateLeaf = (function () {
    function StateLeaf(pubKey, voteOptionTreeRoot, voiceCreditBalance, nonce) {
        var _this = this;
        this.asArray = function () {
            return _this.pubKey.asArray().concat([
                _this.voteOptionTreeRoot,
                _this.voiceCreditBalance,
                _this.nonce,
            ]);
        };
        this.asCircuitInputs = function () {
            return _this.asArray();
        };
        this.hash = function () {
            return maci_crypto_1.hash(_this.asArray());
        };
        this.pubKey = pubKey;
        this.voteOptionTreeRoot = voteOptionTreeRoot;
        this.voiceCreditBalance = voiceCreditBalance;
        this.nonce = nonce;
    }
    StateLeaf.genFreshLeaf = function (pubKey, voteOptionTreeRoot, voiceCreditBalance) {
        return new StateLeaf(pubKey, voteOptionTreeRoot, maci_crypto_1.bigInt(voiceCreditBalance), maci_crypto_1.bigInt(0));
    };
    StateLeaf.genRandomLeaf = function () {
        return new StateLeaf(new PubKey([maci_crypto_1.genRandomSalt(), maci_crypto_1.genRandomSalt()]), maci_crypto_1.genRandomSalt(), maci_crypto_1.genRandomSalt(), maci_crypto_1.genRandomSalt());
    };
    return StateLeaf;
})();
exports.StateLeaf = StateLeaf;
/*
 * Unencrypted data whose fields include the user's public key, vote etc.
 */
var Command = (function () {
    function Command(stateIndex, newPubKey, voteOptionIndex, newVoteWeight, nonce, salt) {
        var _this = this;
        if (salt === void 0) { salt = maci_crypto_1.genRandomSalt(); }
        this.asArray = function () {
            return [
                _this.stateIndex
            ].concat(_this.newPubKey.asArray(), [
                _this.voteOptionIndex,
                _this.newVoteWeight,
                _this.nonce,
                _this.salt,
            ]);
        };
        /*
         * Check whether this command has deep equivalence to another command
         */
        this.equals = function (command) {
            return _this.stateIndex == command.stateIndex &&
                _this.newPubKey[0] == command.newPubKey[0] &&
                _this.newPubKey[1] == command.newPubKey[1] &&
                _this.voteOptionIndex == command.voteOptionIndex &&
                _this.newVoteWeight == command.newVoteWeight &&
                _this.nonce == command.nonce &&
                _this.salt == command.salt;
        };
        /*
         * Signs this command and returns a Signature.
         */
        this.sign = function (privKey) {
            return maci_crypto_1.sign(privKey.rawPrivKey, maci_crypto_1.hash(_this.asArray()));
        };
        /*
         * Returns true if the given signature is a correct signature of this
         * command and signed by the private key associated with the given public
         * key.
         */
        this.verifySignature = function (signature, pubKey) {
            return maci_crypto_1.verifySignature(maci_crypto_1.hash(_this.asArray()), signature, pubKey.rawPubKey);
        };
        /*
         * Encrypts this command along with a signature to produce a Message.
         */
        this.encrypt = function (signature, sharedKey) {
            var plaintext = _this.asArray().concat([
                signature.R8[0],
                signature.R8[1],
                signature.S,
            ]);
            var ciphertext = maci_crypto_1.encrypt(plaintext, sharedKey);
            var message = new Message(ciphertext.iv, ciphertext.data);
            return message;
        };
        this.stateIndex = stateIndex;
        this.newPubKey = newPubKey;
        this.voteOptionIndex = voteOptionIndex;
        this.newVoteWeight = newVoteWeight;
        this.nonce = nonce;
        this.salt = salt;
    }
    /*
     * Decrypts a Message to produce a Command.
     */
    Command.decrypt = function (message, sharedKey) {
        var decrypted = maci_crypto_1.decrypt(message, sharedKey);
        var command = new Command(decrypted[0], new PubKey([decrypted[1], decrypted[2]]), decrypted[3], decrypted[4], decrypted[5], decrypted[6]);
        var signature = {
            R8: [decrypted[7], decrypted[8]],
            S: decrypted[9]
        };
        return { command: command, signature: signature };
    };
    return Command;
})();
exports.Command = Command;

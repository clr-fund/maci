import {
    Command,
    Message,
    Keypair,
    PrivKey,
} from '../'

import {
    encrypt,
    sign,
    decrypt,
    verifySignature,
    genKeypair,
    bigInt,
} from 'maci-crypto'

describe('Domain objects', () => {
    const { privKey, pubKey } = new Keypair()
    const k = new Keypair()

    const privKey1 = k.privKey
    const pubKey1 = k.pubKey

    const encKeypair = new Keypair()
    const encPrivKey = k.privKey
    const encPubKey = k.pubKey

    const newKeypair = new Keypair()
    const newPrivKey = k.privKey
    const newPubKey = k.pubKey

    const ecdhSharedKey = Keypair.genEcdhSharedKey(privKey, pubKey1)

    const command: Command = new Command(
        bigInt(10),
        newPubKey,
        bigInt(0),
        bigInt(9),
        bigInt(123),
    )

    describe('Keypairs', () => {
        it('the Keypair constructor should generate a random keypair if not provided a private key', () => {
            const k1 = new Keypair()
            const k2 = new Keypair()

            expect(k1.equals(k2)).toBeFalsy()

            expect(k1.privKey.rawPrivKey).not.toEqual(k2.privKey.rawPrivKey)
        })

        it('the Keypair constructor should generate the correct public key given a private key', () => {
            const rawKeyPair = genKeypair()
            const k = new Keypair(new PrivKey(rawKeyPair.privKey))
            expect(rawKeyPair.pubKey[0]).toEqual(k.pubKey.rawPubKey[0])
            expect(rawKeyPair.pubKey[1]).toEqual(k.pubKey.rawPubKey[1])
        })
    })

    describe('Commands and Messages', () => {
        const signature = command.sign(privKey)
        const message = command.encrypt(signature, ecdhSharedKey)
        const decrypted = Command.decrypt(message, ecdhSharedKey)

        it ('command.sign() should produce a valid signature', () => {
            expect(command.verifySignature(signature, pubKey)).toBeTruthy()
        })
        
        it ('A decrypted message should match the original command', () => {
            expect(decrypted.command.equals(command)).toBeTruthy()
            expect(decrypted.signature.R8[0]).toEqual(signature.R8[0])
            expect(decrypted.signature.R8[1]).toEqual(signature.R8[1])
            expect(decrypted.signature.S).toEqual(signature.S)
        })

        it ('A decrypted message should have a valid signature', () => {
            expect(decrypted.command.verifySignature(decrypted.signature, pubKey)).toBeTruthy()
        })
    })
})

const { request } = require('express')
const app = require('./app')
const crypto = require('crypto')
const biginteger = require('./public/js/bigint')


const rbigint = (nbytes) => biginteger.leBuff2int(crypto.randomBytes(nbytes))
const toHex = (number, length = 32) =>
  '0x' +
  (number instanceof Buffer ? number.toString('hex') : bigInt(number).toString(16)).padStart(length * 2, '0')


async function start_test(){
    commitments = [];
    for( i=1; i<4 ; i++){
        console.log("====>    " + i + "s Commitment is creating...")

        let rnd1 = rbigint(31);
        let rnd2 = rbigint(31);
        console.log("--> nullifier:\n", rnd1, "\n--> secret:\n",rnd2)
        let  u = await app.generateCommitment(rnd1, rnd2)
        console.log("--> commitment:\n", u.commitment)
        console.log("--> Hex commitment:\n", toHex(u.preimage, 62))

        commitments.push(u)

        await app.deposit(u)
    }

    let commitment_index = Math.floor(Math.random() * (commitments.length ))
    let candid = commitments[commitment_index]
    console.log("====>  this commitment selected to generate proof:   \n", candid.commitment)

    let {publicSignals, proof} = await app.generateProof(candid)

    app.verifyProof(publicSignals, proof)

}

start_test()

const fs = require('fs')
const crypto = require('crypto')
const MerkleTree = require('fixed-merkle-tree')
const snarkjs = require('snarkjs')
const circomlibjs = require('circomlibjs')
const biginteger = require('./public/js/bigint')
const ffjavascript = require("ffjavascript");


const stringifyBigInts = ffjavascript.utils.stringifyBigInts;
const F = new ffjavascript.ZqField(
  ffjavascript.Scalar.fromString(
    "21888242871839275222246405745257275088548364400416034343698204186575808495617"
  )
);
const toHex = (number, length = 32) =>
  '0x' +
  (number instanceof Buffer ? number.toString('hex') : bigInt(number).toString(16)).padStart(length * 2, '0')

const rbigint = (nbytes) => biginteger.leBuff2int(crypto.randomBytes(nbytes))

let nullifierHash_list = [];
let tree = new MerkleTree(20);
console.log("=> Tree Created with levels:", tree.levels, "\n");

async function deposit(deposit){
    tree.insert(deposit.commitment)
    console.log("====>    commitment inserted to tree   \n")
        // fs.writeFileSync("keys/input0.json", JSON.stringify(input))
}

async function generateCommitment(nullifier, secret) {
    let deposit = {
      secret: secret,
      nullifier: nullifier,
    }
    deposit.preimage = Buffer.concat([deposit.nullifier.leInt2Buff(31), deposit.secret.leInt2Buff(31)])
    deposit.commitment = await pedersenHash(deposit.preimage)
    deposit.nullifierHash = await pedersenHash(deposit.nullifier.leInt2Buff(31))
    return deposit
}

async function pedersenHash(data){
    const babyJub = await circomlibjs.buildBabyjub()
    const pedHash = await circomlibjs.buildPedersenHash()
    return F.fromRprLEM(pedHash.babyJub.unpackPoint(pedHash.hash(data))[0])
}

function Uint8Array_to_bigint(x) {
    var ret = 0n;
    for (var idx = 0; idx < x.length; idx++) {
      ret = ret * 256n;
      ret = ret + BigInt(x[idx]);
    }
    return ret;
}

async function generateProof(deposit) {
    const circuit_wasm = fs.readFileSync('keys/circuit.wasm');
    const circuit_final = fs.readFileSync('keys/circuit_final.zkey');

    let index = tree.indexOf(deposit.commitment)

    if(index < 0) return "The deposit is not found in the tree";
    // if(tree.length > 2**20 - 1) return "merkletree is full";
    if(nullifierHash_list.find((element) => element === deposit.nullifierHash.toString())) return "The commitment is already spent";

    const {pathElements, pathIndices } = tree.path(index);

    const input =  stringifyBigInts({
        root: tree.root(),
        nullifierHash: deposit.nullifierHash, 

        //private
        nullifier: deposit.nullifier,
        secret: deposit.secret,
        pathElements: pathElements,
        pathIndices: pathIndices,
    })

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, circuit_wasm, circuit_final);

    console.log("--> Proof is created: ");
    console.log(JSON.stringify(proof, null, 1));

    return {publicSignals, proof}

}

async function verifyProof(publicSignals, proof){
    const verification_key = fs.readFileSync('keys/verification_key.json');
    const vKey = JSON.parse(verification_key);

    const res = await snarkjs.groth16.verify(vKey, publicSignals, proof);
    
    if (res === true) {
        console.log("\n====> Verify result:  Verification OK ");
        nullifierHash_list.push(publicSignals[1])
        return "Verification OK"
    } else {
        console.log("\n====> Verify result: Invalid proof ");
        return "Invalid proof"
    }
}

async function parseNote(note){
    note = note.slice(2)
    const buf = Buffer.from(note, 'hex')
    const nullifier = biginteger.leBuff2int(buf.slice(0,31));
    const secret = biginteger.leBuff2int(buf.slice(31, 62));
    // console.log(note,buf.length, nullifier, secret)
    return await generateDeposit(nullifier, secret);
}

module.exports = {
    generateCommitment,
    deposit,
    generateProof,
    verifyProof,
    tree
}
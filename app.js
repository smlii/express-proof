
const fs = require('fs')
const crypto = require('crypto')
const MerkleTree = require('fixed-merkle-tree')
const snarkjs = require('snarkjs')
const circomlib = require('circomlib')
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

let commitment_list = (fs.readFileSync("commitments.txt", 'utf-8')).split(",");
let nullifierHash_list = (fs.readFileSync("nullifierHash.txt", 'utf-8')).split(",");

var multer = require('multer')
var upload = multer()
var bodyParser = require('body-parser');
const express = require('express')
const path = require('path')
const app = express()
const port = 3000
// var things = require('./things.js')
// app.use('/things', things)
app.use(express.static(path.join(__dirname,'public')));
app.use(upload.array());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.set('view engine', 'pug');
app.set('views','./views');

app.get('/', (req, res) => {
    res.render('view', {
        title: "Proof",
        area: "",
    });
})
app.post('/gen_proof', async function (req, res){
    let dep = await parseNote(req.body.search)
    let result = await deposit(dep)
    res.render("view", {
        area: result
    })
})
app.get("/generateCommitment", async (req, res) => {
    let dep = await generateDeposit(rbigint(31), rbigint(31));
    // let tree =  await deposit(dep)
    commitment_list.push(dep.commitment.toString())
    fs.writeFileSync("commitments.txt", commitment_list.toString())

    res.render('view', {
        title: 'Proof',
        area: toHex(dep.preimage, 62)
    })
})
app.post("/verify", async (req, res) => {
    let proof = JSON.parse(req.body.proofinput)
    let publicSignals = JSON.parse(req.body.publicinput)
    let result = await verifyProof(publicSignals, proof)

    res.render('view', {
        area: result
    })
})
app.listen(port, async () => {
    console.log(`Example app listening on port ${port}`)
    

})

async function deposit(deposit){
    
    let tree = new MerkleTree(20, commitment_list);
    // tree.bulkInsert(commitment_list);
    let index = commitment_list.findIndex(leaf => leaf === deposit.commitment.toString())

    if(index < 0) return "The deposit is not found in the tree";
    if(commitment_list.length > 2**20 - 1) return "merkletree is full";
    if(nullifierHash_list.find((element) => element === deposit.nullifierHash.toString())) return "The commitment is already spent";

    const {pathElements, pathIndices } = tree.path(index);

    const input =  stringifyBigInts({
        root: tree.root(),
        nullifierHash: deposit.nullifierHash, 
        relayer: 0,
        recipient:0,
        fee:0,
        refund:0,

        //private
        nullifier: deposit.nullifier,
        secret: deposit.secret,
        pathElements: pathElements,
        pathIndices: pathIndices,
    })
    fs.writeFileSync("keys/input0.json", JSON.stringify(input))
    return generateProof(input)
}

async function generateDeposit(nullifier, secret) {
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

  async function generateProof(input) {
    const circuit_wasm = fs.readFileSync('keys/circuit.wasm');
    const circuit_final = fs.readFileSync('keys/circuit_final.zkey');

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, circuit_wasm, circuit_final);

    // publicSignals[0] = "16552448406442644177807943387438705606130963537105411823368540403522944252748"
    console.log("Proof: ");
    console.log(JSON.stringify(proof, null, 1));

    return "public signals: \n" + JSON.stringify(publicSignals) + "\n proof: \n" +  JSON.stringify(proof)

}
async function verifyProof(publicSignals, proof){
    const verification_key = fs.readFileSync('keys/verification_key.json');
    const vKey = JSON.parse(verification_key);

    const res = await snarkjs.groth16.verify(vKey, publicSignals, proof);

    if (res === true) {
        console.log("Verification OK");
        nullifierHash_list.push(publicSignals[1])
        fs.writeFileSync("nullifierHash.txt", nullifierHash_list.toString());
        return "Verification OK"
    } else {
        console.log("Invalid proof");
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
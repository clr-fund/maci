// @flow
import type { Pool } from 'pg'

const { mimc7 } = require('circomlib')

const { stringifyBigInts, unstringifyBigInts } = require('./helpers')

class MerkleTree {
  /*  Creates an optimized MerkleTree with `treeDepth` depth,
   *  of which are initialized with the initial value `zeroValue`.
   *
   *  i.e. the 0th level is initialized with `zeroValue`,
   *       and the 1st level is initialized with
   *       hashLeftRight(`zeroValue`, `zeroValue`)
   */
  constructor (depth: Number, zeroValue: BigInt) {
    this.depth = depth
    this.zeroValue = zeroValue
    this.leaves = [] // Hash value of the leaves
    this.leafNumber = Math.pow(2, depth)

    // Values to create the hash values of the leaves
    // NOTE: encryptedValues contains values of the encrypted values
    this.encryptedValues = []
    // Public keys used to decrypt the encrypted values
    // (decryption key is generated via ecdh)
    this.ecdhPublicKeys = []

    this.zeros = {
      0: zeroValue
    }
    this.filledSubtrees = {
      0: zeroValue
    }
    this.filledPaths = {
      0: {}
    }

    for (let i = 1; i < depth; i++) {
      this.zeros[i] = this.hashLeftRight(this.zeros[i - 1], this.zeros[i - 1])
      this.filledSubtrees[i] = this.zeros[i]
      this.filledPaths[i] = {}
    }

    this.root = this.hashLeftRight(
      this.zeros[this.depth - 1],
      this.zeros[this.depth - 1]
    )

    this.nextIndex = 0
  }

  /*  Helper function to hash the left and right values
   *  of the leaves
   */
  hashLeftRight (left: BigInt, right: BigInt): BigInt {
    return mimc7.multiHash([left, right])
  }

  /* Inserts a new value into the merkle tree */
  insert (encryptedValue: Array<BigInt>, publicKey: Array<BigInt>) {
    const leaf = mimc7.multiHash(encryptedValue)

    let curIdx = this.nextIndex
    this.nextIndex += 1

    let currentLevelHash = leaf
    let left
    let right

    for (let i = 0; i < this.depth; i++) {
      if (curIdx % 2 === 0) {
        left = currentLevelHash
        right = this.zeros[i]

        this.filledSubtrees[i] = currentLevelHash

        this.filledPaths[i][curIdx] = left
        this.filledPaths[i][curIdx + 1] = right
      } else {
        left = this.filledSubtrees[i]
        right = currentLevelHash

        this.filledPaths[i][curIdx - 1] = left
        this.filledPaths[i][curIdx] = right
      }

      currentLevelHash = this.hashLeftRight(left, right)
      curIdx = parseInt(curIdx / 2)
    }

    this.root = currentLevelHash
    this.leaves.push(leaf)
    this.encryptedValues.push(encryptedValue)
    this.ecdhPublicKeys.push(publicKey)
  }

  /* Updates merkletree leaf at `leafIndex` with `newLeafValue` */
  update (
    leafIndex: Number,
    encryptedValue: Array<BigInt>,
    publicKey: Array<BigInt>
  ) {
    if (leafIndex >= this.nextIndex) {
      throw new Error("Can't update leafIndex which hasn't been inserted yet!")
    }

    // eslint-disable-next-line no-unused-vars
    const [path, _] = this.getPathUpdate(leafIndex)

    this._update(
      leafIndex,
      encryptedValue,
      publicKey,
      path
    )
  }

  /*  _Verbose_ API to update the value of the leaf in the current tree.
   *  The reason why its so verbose is because I wanted to maintain compatibility
   *  with the merkletree smart contract obtained from semaphore.
   *  (https://github.com/kobigurk/semaphore/blob/2933bce0e41c6d4df82b444b66b4e84793c90893/semaphorejs/contracts/MerkleTreeLib.sol)
   *  It is also very expensive to update if we do it naively on the EVM
   */
  _update (
    leafIndex: Number,
    encryptedValue: Array<BigInt>,
    publicKey: Array<BigInt>,
    path: Array<BigInt>
  ) {
    if (leafIndex >= this.nextIndex) {
      throw new Error("Can't update leafIndex which hasn't been inserted yet!")
    }

    // Get leaf hash value
    const leaf = mimc7.multiHash(encryptedValue)

    let curIdx = leafIndex
    let currentLevelHash = this.leaves[leafIndex]
    let left
    let right

    for (let i = 0; i < this.depth; i++) {
      if (curIdx % 2 === 0) {
        left = currentLevelHash
        right = path[i]
      } else {
        left = path[i]
        right = currentLevelHash
      }

      currentLevelHash = this.hashLeftRight(left, right)
      curIdx = parseInt(curIdx / 2)
    }

    if (this.root !== currentLevelHash) {
      throw new Error('MerkleTree: tree root / current level has mismatch')
    }

    curIdx = leafIndex
    currentLevelHash = leaf

    for (let i = 0; i < this.depth; i++) {
      if (curIdx % 2 === 0) {
        left = currentLevelHash
        right = path[i]

        this.filledPaths[i][curIdx] = left
        this.filledPaths[i][curIdx + 1] = right
      } else {
        left = path[i]
        right = currentLevelHash

        this.filledPaths[i][curIdx - 1] = left
        this.filledPaths[i][curIdx] = right
      }

      currentLevelHash = this.hashLeftRight(left, right)
      curIdx = parseInt(curIdx / 2)
    }

    this.root = currentLevelHash
    this.leaves[leafIndex] = leaf
    this.encryptedValues[leafIndex] = encryptedValue
    this.ecdhPublicKeys[leafIndex] = publicKey
  }

  /*  Gets the path needed to construct a the tree root
   *  Used for quick verification on updates.
   *  Runs in O(log(N)), where N is the number of leaves
   */
  getPathUpdate (leafIndex: Number): [Array<BigInt>, Array<Number>] {
    if (leafIndex >= this.nextIndex) {
      throw new Error('Path not constructed yet, leafIndex >= nextIndex')
    }

    let curIdx = leafIndex
    const path = []
    const pathPos = []

    for (let i = 0; i < this.depth; i++) {
      if (curIdx % 2 === 0) {
        path.push(this.filledPaths[i][curIdx + 1])
        pathPos.push(0)
      } else {
        path.push(this.filledPaths[i][curIdx - 1])
        pathPos.push(1)
      }
      curIdx = parseInt(curIdx / 2)
    }

    return [path, pathPos]
  }
}

// Helper function to abstract away `new` keyword for API
const createMerkleTree = (
  treeDepth: Number,
  zeroValue: BigInt
): MerkleTree => new MerkleTree(treeDepth, zeroValue)

// Helper function to save merkletree into a database
const saveMerkleTreeToDb = async (
  pool: Pool,
  mkName: String,
  mk: MerkleTree
) => {
  // See if there's alrea
  const mkQuery = {
    text: `INSERT INTO
      merkletrees(
        name,
        depth,
        next_index,
        root,
        zero_value,
        zeros,
        filled_sub_trees,
        filled_paths
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8
      ) ON CONFLICT (name) DO UPDATE SET
        name = excluded.name,
        depth = excluded.depth,
        next_index = excluded.next_index,
        root = excluded.root,
        zero_value = excluded.zero_value,
        zeros = excluded.zeros,
        filled_sub_trees = excluded.filled_sub_trees,
        filled_paths = excluded.filled_paths
      ;`,
    values: [
      mkName,
      mk.depth,
      mk.nextIndex,
      stringifyBigInts(mk.root),
      stringifyBigInts(mk.zeroValue),
      stringifyBigInts(mk.zeros),
      stringifyBigInts(mk.filledSubtrees),
      stringifyBigInts(mk.filledPaths)
    ]
  }

  // Saves merkle tree state
  await pool.query(mkQuery)

  // Get merkletree id from db
  const mkTreeRes = await pool.query({
    text: 'SELECT * FROM merkletrees WHERE name = $1 LIMIT 1;',
    values: [mkName]
  })
  const mkTreeId = mkTreeRes.rows[0].id

  // Current leaf index
  const leafIdx = mk.nextIndex - 1

  const leafQuery = {
    text: `INSERT INTO 
        leaves(merkletree_id, index, data, public_key, hash)
        VALUES($1, $2, $3, $4, $5)
        `,
    values: [
      mkTreeId,
      leafIdx,
      { data: stringifyBigInts(mk.encryptedValues[leafIdx]) },
      stringifyBigInts(mk.ecdhPublicKeys[leafIdx]),
      stringifyBigInts(mk.leaves[leafIdx])
    ]
  }

  // Saves latest leaf to merkletree id
  await pool.query(leafQuery)
}

// Help function to load merkletree from a database
const loadMerkleTreeFromDb = async (
  pool: Pool,
  mkName: String,
): MerkleTree => {
  const mkQuery = {
    text: 'SELECT * FROM merkletrees WHERE name = $1 LIMIT 1;',
    values: [mkName]
  }
  const mkResp = await pool.query(mkQuery)

  if (mkResp.rows.length === 0) {
    throw new Error(`MerkleTree named ${mkName} not found in database`)
  }

  // Get MerkleTree result
  const mkRes = mkResp.rows[0]
  const mkResBigInt = unstringifyBigInts(mkResp.rows[0])

  const mk = createMerkleTree(
    mkRes.depth,
    mkResBigInt.zero_value
  )

  mk.nextIndex = mkRes.next_index
  mk.root = mkResBigInt.root
  mk.zeros = mkResBigInt.zeros
  mk.filledSubtrees = mkResBigInt.filled_sub_trees
  mk.filledPaths = mkResBigInt.filled_paths

  // Get leaves
  const leavesQuery = {
    text: 'SELECT * FROM leaves WHERE merkletree_id = $1 ORDER BY index ASC;',
    values: [mkRes.id]
  }
  const leavesResp = await pool.query(leavesQuery)

  // Get leaves values
  const leaves = leavesResp.rows.map((x: Any): BigInt => unstringifyBigInts(x.hash))
  const encryptedValues = leavesResp.rows.map((x: Any): Array<BigInt> => unstringifyBigInts(x.data).data)
  const ecdhPublicKeys = leavesResp.rows.map((x: Any): Array<BigInt> => unstringifyBigInts(x.public_key))

  mk.leaves = leaves
  mk.encryptedValues = encryptedValues
  mk.ecdhPublicKeys = ecdhPublicKeys

  return mk
}

module.exports = {
  createMerkleTree,
  saveMerkleTreeToDb,
  loadMerkleTreeFromDb,
  MerkleTree
}

# Radix Sparse Merkle Tree (RSMT) with Consistency Proofs
#
# This module implements an add-only, path compressed Patricia / radix
# Merkle trie for highly sparse, like 256-bit keys, supporting efficint
# batch insertions and cryptographically secure consistency proofs

# A Consistency Proof π demonstrates that a new set of leaf entries (the batch B)
# was correctly inserted into a previous tree state (with root ρ_0), resulting in a
# new tree state (root ρ_1), without modifying or deleting any pre-existing
# records. This is achieved by generating a topological trace of the insertion
# and evaluating two synchronous hash reconstruction passes over it.
#
# 1. Path Encoding
# Let d be the fixed depth of the tree space. Each edge traverses a bit of the
# key domain. To represent paths of variable length k <= d , we
# encode bit-strings as positive integers with a sentinel high bit:
#     path(k, bits) = (1 << k) | bits
#
# 2. Proof Format
# The proof π is a serialized flat list of operation codes generated via a pre-order
# traversal of the tree changes during batch insertion:
#   - 'S':   Subtree with no changes. Outputs `['S', hash]`.
#   - 'N':   New branch node instantiated. Outputs `['N', common_prefix]`.
#   - 'L':   New leaf inserted. Outputs `['L', key]`.
#   - 'BL':  Border leaf (an existing pre-insertion leaf pushed deeper by a
#            path overlap, not present in B). Outputs `['BL', old_path, key, value]`.
#   - 'BNS': Border Node Shortened (an existing branch whose common prefix was
#            fractured inside by a new junction). Outputs `['BNS', old_path, new_path, lh, rh]`.
#
# 3. Proof Verification
# To verify consistency, the prover supplies the initial root ρ_0, the final root ρ_1,
# the batch of new leaves B = {(k_1, v_1), ..., (k_n, v_n)}, and the consistency proof π.
# The verifier performs an one-pass evaluation through the opcode trace to compute pre-
# and post- batch insertion root hashes (r_0, r_1):
#
# Let Eval(π, B, start_bit) -> (h_0, h_1) be the recursive evaluation function,
# returning the pre-insertion hash h_0 and post-insertion hash h_1 of the sub-tree.
# Let remaining_path(key) = (1 << (d - start_bit)) | (key >> start_bit).
#
#   - 'S': pop(hash) -> return (hash, hash)
#   - 'N': pop(cp). Evaluating children yields (lh_0, lh_1) and (rh_0, rh_1).
#          - If lh_0 and rh_0 are both null (this branch didn't exist in ρ_0), h_0 = null.
#          - If exactly one of lh_0, rh_0 is null, pass the other strictly through
#            (path compression pass-through rule).
#          - Otherwise, h_0 = HashNode(cp, lh_0, rh_0).
#          - h_1 = HashNode(cp, lh_1, rh_1).
#   - 'L': pop(key), extract value corresponding to key from batch subset B.
#          - h_0 = null (leaf didn't exist).
#          - h_1 = HashLeaf(remaining_path(key), value).
#   - 'BL': pop(old_path, key, value). (This leaf was already in the tree).
#           - h_0 = HashLeaf(old_path, value) (its previous compressed location).
#           - h_1 = HashLeaf(remaining_path(key), value) (its new location in ρ_1).
#   - 'BNS': pop(old_path, new_path, lh, rh). Evaluate inner subtree -> (inner_0, inner_1).
#            - Require inner_0 == HashNode(new_path, lh, rh) (cryptographic continuation).
#            - h_0 = HashNode(old_path, lh, rh).
#            - h_1 = inner_1.
#
# The consistency proof is valid iff:
#   (1) Eval algorithm fully consumes both π and B without leftovers,
#   (2) The computed root tuple (r_0, r_1) exactly equals (ρ_0, ρ_1).

import hashlib
import sys

# ---------------------------------------------------------------------------
# Minimal CBOR encoder (handles None, unsigned int, bytes, list)
# ---------------------------------------------------------------------------

def cbor_encode(value):
    """Encode a value as CBOR bytes. Supports None, int >= 0, bytes, list."""
    if value is None:
        return b'\xf6'                                      # CBOR null
    if isinstance(value, int):
        if value < 0:
            raise ValueError("negative integers not supported")
        if value < 2**64:
            return _cbor_head(0, value)                     # major 0: uint
        n = (value.bit_length() + 7) // 8
        return b'\xc2' + cbor_encode(value.to_bytes(n, 'big'))
    if isinstance(value, (bytes, bytearray)):
        return _cbor_head(2, len(value)) + value            # major 2: bstr
    if isinstance(value, (list, tuple)):
        body = b''.join(cbor_encode(v) for v in value)
        return _cbor_head(4, len(value)) + body             # major 4: array
    raise TypeError(f"cbor_encode: unsupported {type(value)}")

def _cbor_head(major, n):
    m = major << 5
    if n < 24:       return bytes([m | n])
    if n < 0x100:    return bytes([m | 24, n])
    if n < 0x10000:  return bytes([m | 25]) + n.to_bytes(2, 'big')
    if n < 2**32:    return bytes([m | 26]) + n.to_bytes(4, 'big')
    return bytes([m | 27]) + n.to_bytes(8, 'big')

# ---------------------------------------------------------------------------
# Path utilities
# ---------------------------------------------------------------------------

def path_len(p):
    """Number of payload bits (excluding sentinel)."""
    return p.bit_length() - 1

def path_as_bytes(p):
    """Serialize sentinel-encoded path as big-endian bytes for hashing."""
    return p.to_bytes((p.bit_length() + 7) // 8, 'big')

# ---------------------------------------------------------------------------
# Hashing (Go aggregator compatible)
# ---------------------------------------------------------------------------

EMPTY = None

def hash_leaf(path, value):
    """H(CBOR([path_bytes, value_bytes])) — position-dependent leaf hash."""
    return hashlib.sha256(cbor_encode([path_as_bytes(path), value])).digest()

def hash_node(path, lh, rh):
    """H(CBOR([path_bytes, lh_or_null, rh_or_null])) — no pass-through."""
    return hashlib.sha256(cbor_encode([path_as_bytes(path), lh, rh])).digest()

# ---------------------------------------------------------------------------
# Node types
# ---------------------------------------------------------------------------

class LeafBranch:
    """Leaf node: stores key, value, remaining path, and cached hash."""
    __slots__ = ['path', 'key', 'value', '_hash']

    def __init__(self, path, key, value):
        self.path  = path
        self.key   = key
        self.value = value
        self._hash = hash_leaf(path, value)

    def get_hash(self):
        return self._hash

    def rehash(self, new_path):
        """Called when a node-split shortens this leaf's path."""
        self.path  = new_path
        self._hash = hash_leaf(new_path, self.value)


class NodeBranch:
    """Internal node: common-prefix path + left/right children."""
    __slots__ = ['path', 'left', 'right', '_hash']

    def __init__(self, path, left, right):
        self.path  = path
        self.left  = left
        self.right = right
        self._hash = None

    def get_hash(self):
        if self._hash is None:
            lh = self.left.get_hash()  if self.left  else None
            rh = self.right.get_hash() if self.right else None
            if lh is None and rh is None:
                return None
            self._hash = hash_node(self.path, lh, rh)
        return self._hash

# ---------------------------------------------------------------------------
# Sparse Merkle Tree
# ---------------------------------------------------------------------------

class SparseMerkleTree:
    """
    Radix SMT. LSB-first path consumption.
    Append-only (no deletion, no value changes).  In-memory; no persistence.
    """
    def __init__(self, depth=256):
        self.depth = depth
        self.root  = None

    def get_root(self):
        return self.root.get_hash() if self.root else None

    # ------------------------------------------------------------------
    # Public API: batch insert
    # ------------------------------------------------------------------

    def batch_insert(self, batch):
        """
        Insert a batch of (key, value) pairs.  Duplicates / pre-existing keys are skipped.

        Returns (items, proof_tree) where:
          items     = [(key, value), ...] sorted unique inserted pairs
          proof_tree = recursive proof structure (see module docstring)

        Use verify_consistency(proof_tree, old_root, new_root, items, depth).
        """
        new_items = {}
        for key, data in batch:
            if key in new_items:
                print(f"Duplicate key {key} in batch, skipping.", file=sys.stderr)
                continue
            if self._find_leaf(key) is not None:
                print(f"Key {key} already exists, skipping.", file=sys.stderr)
                continue
            new_items[key] = data

        if not new_items:
            return [], ['S', None]   # empty proof: nothing changed

        items = sorted(new_items.items())
        proof_out = []
        self.root = self._insert_proof(self.root, items, 0, proof_out)
        return items, proof_out

    # ------------------------------------------------------------------
    # Public API: single-key inclusion proof (Go MerkleTreePath format)
    # ------------------------------------------------------------------

    def generate_proof(self, key):
        """
        Returns steps = [(path, data), ...] leaf-to-root, or None if absent.
          step[0]: (leaf.path, leaf.value)
          step[i>0]: (node.path, sibling_hash|None)
        """
        steps = []
        if not self._collect_proof(self.root, key, 0, steps):
            return None
        return steps

    def _collect_proof(self, node, key, start_bit, steps):
        if node is None:
            return False
        if isinstance(node, LeafBranch):
            if node.key != key:
                return False
            steps.append((node.path, node.value))
            return True
        n    = path_len(node.path)
        kpfx = (key >> start_bit) & ((1 << n) - 1)
        npfx = node.path           & ((1 << n) - 1)
        if kpfx != npfx:
            return False
        bit  = start_bit + n
        direction = (key >> bit) & 1
        bit += 1
        if direction:
            found = self._collect_proof(node.right, key, bit, steps)
            sib   = node.left.get_hash()  if node.left  else None
        else:
            found = self._collect_proof(node.left,  key, bit, steps)
            sib   = node.right.get_hash() if node.right else None
        if found:
            steps.append((node.path, sib))
        return found

    # ------------------------------------------------------------------
    # Internal: key lookup
    # ------------------------------------------------------------------

    def _find_leaf(self, key):
        node = self.root
        bit  = 0
        while node is not None:
            if isinstance(node, LeafBranch):
                return node if node.key == key else None
            n    = path_len(node.path)
            kpfx = (key >> bit) & ((1 << n) - 1)
            npfx = node.path    & ((1 << n) - 1)
            if kpfx != npfx:
                return None
            bit += n
            direction = (key >> bit) & 1
            bit += 1
            node = node.right if direction else node.left
        return None

    # ------------------------------------------------------------------
    # Internal: path helpers
    # ------------------------------------------------------------------

    def _rem(self, key, start_bit):
        return (1 << (self.depth - start_bit)) | (key >> start_bit)

    @staticmethod
    def _first_split(keys, start_bit):
        """First bit >= start_bit where the sorted keys disagree."""
        result = None
        for i in range(len(keys) - 1):
            xor = (keys[i] ^ keys[i + 1]) >> start_bit
            if xor:
                pos = start_bit + (xor & -xor).bit_length() - 1
                if result is None or pos < result:
                    result = pos
        return result

    # ------------------------------------------------------------------
    # Internal: build fresh subtree (all-new items, no existing nodes)
    # Also produces the proof sub-tree.
    # border_old_paths: {key: old_path} for leaves that are border leaves.
    # ------------------------------------------------------------------

    def _build_batch_proof(self, batch, start_bit, proof_out, border_old_paths=None):
        """
        Build a maximally compressed Patricia subtree from items in batch.
        Outputs trace directly to proof_out.
        """
        if not batch:
            proof_out.extend(['S', None])
            return None

        if len(batch) == 1:
            k, v = batch[0]
            new_path = self._rem(k, start_bit)
            leaf     = LeafBranch(new_path, k, v)
            old_path = (border_old_paths or {}).get(k)
            if old_path is None:
                proof_out.extend(['L', k])
            else:
                proof_out.extend(['BL', old_path, k, v])
            return leaf

        keys  = [k for k, _ in batch]
        split = self._first_split(keys, start_bit)

        n_common = split - start_bit
        cbits    = (keys[0] >> start_bit) & ((1 << n_common) - 1)
        cp       = (1 << n_common) | cbits

        lb = [(k, v) for k, v in batch if not ((k >> split) & 1)]
        rb = [(k, v) for k, v in batch if      (k >> split) & 1 ]

        proof_out.extend(['N', cp])
        ln = self._build_batch_proof(lb, split + 1, proof_out, border_old_paths)
        rn = self._build_batch_proof(rb, split + 1, proof_out, border_old_paths)
        return NodeBranch(cp, ln, rn)

    # ------------------------------------------------------------------
    # Internal: insert batch into existing subtree, returning proof
    # ------------------------------------------------------------------

    def _insert_proof(self, node, batch, start_bit, proof_out):
        """
        Insert batch (sorted [(key, value)]) into node.
        Appends proof directly to proof_out.
        """
        if not batch:
            proof_out.extend(['S', node.get_hash() if node else None])
            return node

        if node is None:
            return self._build_batch_proof(batch, start_bit, proof_out)

        if isinstance(node, LeafBranch):
            filtered = [(k, v) for k, v in batch if k != node.key]
            if len(filtered) < len(batch):
                print(f"Key {node.key} already exists, skipping.", file=sys.stderr)
            if not filtered:
                proof_out.extend(['S', node.get_hash()])
                return node

            old_path  = node.path
            all_items = sorted([(node.key, node.value)] + filtered,
                               key=lambda x: x[0])
            return self._build_batch_proof(
                all_items, start_bit, proof_out,
                border_old_paths={node.key: old_path})

        n_path      = path_len(node.path)
        node_prefix = node.path & ((1 << n_path) - 1)

        first_div = n_path
        for k, _ in batch:
            item_pfx = (k >> start_bit) & ((1 << n_path) - 1)
            xor      = item_pfx ^ node_prefix
            if xor:
                low = (xor & -xor).bit_length() - 1
                if low < first_div:
                    first_div = low

        if first_div < n_path:
            return self._node_split_proof(node, batch, start_bit, first_div, proof_out)

        split       = start_bit + n_path
        batch_left  = [(k, v) for k, v in batch if not ((k >> split) & 1)]
        batch_right = [(k, v) for k, v in batch if      (k >> split) & 1 ]

        proof_out.extend(['N', node.path])
        new_left  = self._insert_proof(node.left,  batch_left,  split + 1, proof_out)
        new_right = self._insert_proof(node.right, batch_right, split + 1, proof_out)

        node.left  = new_left
        node.right = new_right
        node._hash = None
        return node

    def _node_split_proof(self, node, batch, start_bit, first_div, proof_out):
        n_path      = path_len(node.path)
        node_prefix = node.path & ((1 << n_path) - 1)

        n_common    = first_div
        common_bits = node_prefix & ((1 << n_common) - 1)
        new_cp      = (1 << n_common) | common_bits
        new_split   = start_bit + n_common

        old_dir     = (node_prefix >> n_common) & 1

        old_path = node.path
        lh = node.left.get_hash() if node.left else None
        rh = node.right.get_hash() if node.right else None

        new_path = node.path >> (n_common + 1)
        if new_path == 0:
            new_path = 1
        node.path  = new_path
        node._hash = None

        batch_left  = [(k, v) for k, v in batch if not ((k >> new_split) & 1)]
        batch_right = [(k, v) for k, v in batch if      (k >> new_split) & 1 ]

        proof_out.extend(['N', new_cp])
        if old_dir == 0:
            proof_out.extend(['BNS', old_path, new_path, lh, rh])
            new_left =  self._insert_proof(node,  batch_left,  new_split + 1, proof_out)
            new_right = self._insert_proof(None,  batch_right, new_split + 1, proof_out)
        else:
            new_left =  self._insert_proof(None,  batch_left,  new_split + 1, proof_out)
            proof_out.extend(['BNS', old_path, new_path, lh, rh])
            new_right = self._insert_proof(node,  batch_right, new_split + 1, proof_out)

        return NodeBranch(new_cp, new_left, new_right)


# ---------------------------------------------------------------------------
# Proof root computation
# ---------------------------------------------------------------------------

def synchronized_proof_eval(proof_iterator, depth, batch_dict, start_bit=0):
    """
    Computes both r0 (old root) and r1 (new root) sequentially in one iteration of the proof iterator.
    """
    try:
        tag = next(proof_iterator)
    except StopIteration:
        return None, None

    if tag == 'S': # sibling subree without changes
        h = next(proof_iterator)
        return h, h

    if tag == 'N': # new junction
        cp = next(proof_iterator)
        n_common = cp.bit_length() - 1
        split = start_bit + n_common
        lh0, lh1 = synchronized_proof_eval(proof_iterator, depth, batch_dict, split + 1)
        rh0, rh1 = synchronized_proof_eval(proof_iterator, depth, batch_dict, split + 1)

        # Mode 0 pass-through
        if lh0 is None and rh0 is None: h0 = None
        elif lh0 is None: h0 = rh0
        elif rh0 is None: h0 = lh0
        else: h0 = hash_node(cp, lh0, rh0)

        # Mode 1 normal
        h1 = hash_node(cp, lh1, rh1)
        return h0, h1

    if tag == 'L':   # new leaf
        k = next(proof_iterator)
        v = batch_dict.pop(k, None)
        if v is None:
            raise ValueError(f"Proof requires key {k} not found in pending batch requests")

        new_path = (1 << (depth - start_bit)) | (k >> start_bit)

        h0 = None
        h1 = hash_leaf(new_path, v)
        return h0, h1

    if tag == 'BL':
        old_path = next(proof_iterator)
        k = next(proof_iterator)
        v = next(proof_iterator)

        new_path = (1 << (depth - start_bit)) | (k >> start_bit)

        h0 = hash_leaf(old_path, v)
        h1 = hash_leaf(new_path, v)
        return h0, h1

    if tag == 'BNS':   # border NodeBranch whose common-prefix was shortened by a node-split
        old_path = next(proof_iterator)
        new_path = next(proof_iterator)
        lh = next(proof_iterator)
        rh = next(proof_iterator)

        inner0, inner1 = synchronized_proof_eval(proof_iterator, depth, batch_dict, start_bit)

        # Verify Merkle hash
        expected_shortened_hash = hash_node(new_path, lh, rh)
        if inner0 != expected_shortened_hash:
            print(f"BNS mismatch!", file=sys.stderr)
            print(f"  inner0: {inner0.hex() if inner0 else None}", file=sys.stderr)
            print(f"  expected: {expected_shortened_hash.hex() if expected_shortened_hash else None}", file=sys.stderr)
            raise ValueError("BNS tag forgery: inner0 does not match shortened node hash")

        return hash_node(old_path, lh, rh), inner1

    raise ValueError(f"Unknown tag encountered in flat proof stream: {tag}")


# ---------------------------------------------------------------------------
# Consistency (non-deletion) proof verification
# ---------------------------------------------------------------------------

def verify_consistency(proof, old_root, new_root, batch, depth):
    if not batch:
        return old_root == new_root

    batch_dict = {k: v for k, v in batch}

    proof_iter = iter(proof)
    try:
        r0, r1 = synchronized_proof_eval(proof_iter, depth, batch_dict)
    except Exception as e:
        print(f"Consistency verification failed: {e}", file=sys.stderr)
        return False

    # Ensure all proof elements were consumed and no extra batch items remain
    try:
        next(proof_iter)
        print(f"Consistency verification failed: proof iterator not fully consumed, extra elements found.", file=sys.stderr)
        return False
    except StopIteration:
        pass # Expected behavior if proof is fully consumed

    if batch_dict:
        print(f"Consistency verification failed: {len(batch_dict)} batch elements were not consumed by the proof.", file=sys.stderr)
        return False

    if r0 != old_root:
        print(f"Consistency step 1 failed:\n  computed: {r0.hex() if r0 else None}\n  expected: {old_root.hex() if old_root else None}", file=sys.stderr)
        return False

    if r1 != new_root:
        print(f"Consistency step 2 failed:\n  computed: {r1.hex() if r1 else None}\n  expected: {new_root.hex() if new_root else None}", file=sys.stderr)
        return False

    return True


# ---------------------------------------------------------------------------
# Standalone inclusion proof verification
# ---------------------------------------------------------------------------

def verify_proof(key, value, steps, root, depth):
    """
    Verify a leaf inclusion proof for (key, value) against root.

    steps[0]: (leaf_path, leaf_value)
    steps[i>0]: (node_path, sibling_hash|None)
    """
    if not steps:
        return False
    leaf_path, leaf_value = steps[0]
    if leaf_value != value:
        return False
    current_hash = hash_leaf(leaf_path, leaf_value)
    consumed     = depth - path_len(leaf_path)

    for node_path, sibling_hash in steps[1:]:
        n           = path_len(node_path)
        routing_bit = (key >> (consumed - 1)) & 1
        consumed   -= n + 1
        if routing_bit == 0:
            lh, rh = current_hash, sibling_hash
        else:
            lh, rh = sibling_hash, current_hash
        current_hash = hash_node(node_path, lh, rh)

    return current_hash == root


# Demo / test
# ---------------------------------------------------------------------------

def main():
    import time

    depth = 256
    smt   = SparseMerkleTree(depth)

    def check_batch(label, smt, batch):
        old_root = smt.get_root()
        t0       = time.perf_counter()
        items, proof = smt.batch_insert(batch)
        dt       = time.perf_counter() - t0
        new_root = smt.get_root()

        assert verify_consistency(proof, old_root, new_root, items, depth), \
            f"Consistency proof failed for {label}"

        # Spot-check individual inclusion proofs.
        sample = items[:5] + items[-5:]
        for k, v in sample:
            steps = smt.generate_proof(k)
            assert steps is not None, f"key {k} not found"
            assert verify_proof(k, v, steps, new_root, depth), \
                f"inclusion proof failed for key {k}"

        print(f"{label}: {len(items)} inserted in {dt:.3f}s, "
              f"root={new_root.hex()[:16] if new_root else 'None'}…, "
              f"consistency+inclusion OK", file=sys.stderr)
        return items

    # --- small batch (exercises leaf-split / border leaf case) ---
    check_batch("Small batch", smt, [(1, b'v1'), (3, b'v3'), (2, b'v2')])

    # --- duplicate rejection ---
    smt.batch_insert([(1, b'dup1'), (99, b'new99')])
    assert smt._find_leaf(1)  is not None
    assert smt._find_leaf(99) is not None

    # --- large pre-fill (exercises node-split / border NodeBranch case) ---
    batch = {}
    for i in range(5000):
        rk = hash("a" + str(i)) % (2 ** depth)
        batch[rk] = f"Val {rk}".encode()
    batch[3] = b"dup three"   # duplicate

    check_batch("Pre-fill", smt, batch.items())

    # --- second large batch ---
    batch2 = {hash("b" + str(i)) % (2 ** depth): f"Val2 {i}".encode()
              for i in range(5000)}
    check_batch("Second batch", smt, batch2.items())

    print("All consistency and inclusion proofs verified.", file=sys.stderr)


if __name__ == "__main__":
    main()

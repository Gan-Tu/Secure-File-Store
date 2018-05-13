"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError
import json
from math import ceil

def path_join(strings, separator="/"):
    """Joins a list of strings putting a "/" between each.

    :param strings: a list of strings to join
    :returns: a string
    """
    return separator.join(strings)


class Client(BaseClient):

    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)
        # Get asymmetric keys
        (encrypt_k, decrypt_k), (verify_k, sign_k) = self.get_asymmetric_keys()

        # INITIALIZE KEYFILES FOR KEY NODES IF NECESSARY
        key_dir = "{0}/key_dir".format(self.username)
        if self.storage_server.get(key_dir) is None:
            # Generate new symmetric keys
            ke, km, kn = self.new_symmetric_keys()
            # Encryption of symmetric keys
            C_plaintext = path_join([ke, km, kn], separator="||")
            C = self.crypto.asymmetric_encrypt(C_plaintext, encrypt_k)
            # Sign the Encryption of symmetric keys
            C_sign = self.crypto.asymmetric_sign(C, sign_k)
            D = path_join([C_sign, C], separator="||")
            # Store D on the Storage Server
            self.storage_server.put(key_dir, D)
        else:
            # get keyfile destination
            key_dir = "{0}/key_dir".format(self.username)
            keyfile = self.storage_server.get(key_dir)
            # Check if keyfile exists
            if keyfile is None: raise IntegrityError()
            # Get asymmetric keys
            (_, decrypt_k), (verify_k, _) = self.get_asymmetric_keys()
            # Verify keyfile integrity
            if "||" not in keyfile: raise IntegrityError()
            C_sign, C = keyfile.split("||")
            if not self.crypto.asymmetric_verify(C, C_sign, verify_k):
                raise IntegrityError()
            # Decrypt keyfile
            C = self.crypto.asymmetric_decrypt(C, decrypt_k)
            # Recover symmetric keys
            ke, km, kn = C.split("||")

        # Cache for performance reasons
        self.ke = ke
        self.km = km
        self.kn = kn

        # INITIALIZE SHARE DIRECTORY
        share_dir = "{0}/shares".format(self.username)
        if self.storage_server.get(share_dir) is None:
            shares = dict()
            self.put_shares_directory(shares)
        else:
            # Get symmetric keys
            ke, km, _ = self.get_symmetric_keys()
            # get share_dir destination
            share_dir = "{0}/shares".format(self.username)
            value = self.decrypt_values_at_id(share_dir, ke, km)
            if value is None: raise IntegrityError()
            # Recover symmetric keys
            shares = json.loads(value)
            assert type(shares) == dict, "decoded shares directory must be type dictionary"

        # Cache for performance reasons
        self.shares = shares
        self.trees = dict()

    def resolve(self, uid, ke, km):
        node = self.decrypt_values_at_id(uid, ke, km)
        # resolve pointers until we reach a data node
        while True:
            if node is None:
                return None
            elif self.is_data_node(node):
                return ke, km, uid, node
            elif self.is_pointer_node(node):
                ke, km, uid = self.parse_pointer_node(node)
            else:
                raise IntegrityError()
            node = self.decrypt_values_at_id(uid, ke, km)
      
    def upload(self, name, value):
        # Get symmetric keys
        ke, km, kn = self.get_symmetric_keys()
        # Get ID for the key node of file NAME
        uid = self.get_kid(name, kn)
        # Get Ke, Km, and did for data node
        res = self.resolve(uid, ke, km)
        if res is None:
            # Create new data node
            ke2, km2, _ = self.new_symmetric_keys()
            did = self.new_did()
            key_node_v = "[POINTER]{0}||{1}||{2}".format(ke2, km2, did) 
            key_node_v_enc = self.encrypt_value_for_storage(uid, key_node_v, ke, km)
            self.storage_server.put(uid, key_node_v_enc)
            uid = did
            ke, km = ke2, km2
            isNew = True
        else:
            ke, km, uid, _ = res
            isNew = False

        tree = LocalMerkleTree(self.hash, uid=uid)
        tree.initialize(value, blocksize=1024, uid_gen=self.new_did)

        if name not in self.trees:
            if isNew:
                self.upload_updates(tree.all_nodes(), ke, km)
            else:
                server_root = self.get_server_node(uid, ke, km)
                if tree.length <= server_root["n"]:
                    self.efficient_update(tree, ke, km)
                else:
                    self.delete_server_tree(uid, ke, km)
                    self.upload_updates(tree.all_nodes(), ke, km)
            self.trees[name] = tree
        else:
            if isNew: raise IntegrityError()
            local_tree = self.trees[name]
            server_root = self.get_server_node(uid, ke, km)
            tree.update_uids(local_tree.all_uids())

            if local_tree.hash == server_root["h"]:
                if local_tree.length >= tree.length:
                    self.upload_updates(local_tree.compare_and_update(tree), ke, km)
                    self.trees[name] = local_tree
                else:
                    self.delete_server_tree(uid, ke, km)
                    self.upload_updates(tree.all_nodes(), ke, km)
                    self.trees[name] = tree
            else:
                if local_tree.length >= tree.length:
                    self.efficient_update(tree, ke, km)
                else:
                    self.delete_server_tree(uid, ke, km)
                    self.upload_updates(tree.all_nodes(), ke, km)
                self.trees[name] = tree



    def efficient_update(self, tree, ke, km):
        node = self.get_server_node(tree.uid, ke, km)
        if tree.hash != node["h"]:
            tree.left.uid = node["l"]
            if type(tree.left) is DataNote:
                if node["r"] is not None:
                    self.delete_server_tree(node["r"], ke, km)
                self.upload_updates([(tree.uid, tree.to_string()),
                                     (tree.left.uid, tree.left.to_string())], ke, km)
            else:
                if node["r"] is None: raise IntegrityError()
                tree.right.uid = node["r"]
                self.upload_updates([(tree.uid, tree.to_string())], ke, km)
                
                self.efficient_update(tree.left, ke, km)
                self.efficient_update(tree.right, ke, km)

        
    def download(self, name):
        # Get symmetric keys
        ke, km, kn = self.get_symmetric_keys()
        # Get ID for the key node of file NAME
        uid = self.get_kid(name, kn)
        # Get Ke, Km, and did for data node
        res = self.resolve(uid, ke, km)
        if res is None: return None
        ke, km, uid, node = res
        if not self.is_data_node(node): raise IntegrityError() 

        server_root = self.get_server_node(uid, ke, km)

        # Post Order Traversal        
        data, local_tree = self.server_data(server_root, uid, ke, km)
        self.trees[name] = local_tree

        return data

    def share(self, user, name):
        SYMMETRIC_KEY_LENGTH = 16

        # Get symmetric keys
        ke, km, kn = self.get_symmetric_keys()
        # Get shares directory
        shares = self.get_shares_directory()
        # Get ID for the key node of file NAME
        uid = self.get_kid(name, kn)
        # Get ke, km, uid that NAME links to for this client
        node = self.decrypt_values_at_id(uid, ke, km)
        if self.is_pointer_node(node):
            ke, km, uid = self.parse_pointer_node(node)
        elif not self.is_data_node(node):
            raise IntegrityError()
        # Create value stored at share node
        share_node_v = "[POINTER]{0}||{1}||{2}".format(ke, km, uid) 
        # New key to encrypt share node
        ke2, km2, _ = self.new_symmetric_keys()
        # New share node of id DID
        did = self.new_did()
        # Encrypt share node with new keys
        share_node_v = self.encrypt_value_for_storage(did, share_node_v, ke2, km2)
        # Store share node at a random new data node id: did
        self.storage_server.put(did, share_node_v)

        # Construct the message to share
        msg = "[POINTER]{0}||{1}||{2}".format(ke2, km2, did)
        encrypt_k = self.pks.get_encryption_key(user)
        if encrypt_k is None: raise IntegrityError()
        ciphertext = self.crypto.asymmetric_encrypt(msg, encrypt_k)
        ciphertext_user = path_join([ciphertext, user], separator="/")
        # Sign the encryption
        sig = self.crypto.asymmetric_sign(ciphertext_user, self.rsa_priv_key)

        # Update information about shared node to the directory
        if name not in shares: shares[name] = dict()

        shares[name][user] = {"did": did, "ke": ke2, "km": km2}

        # Update shares directory
        self.put_shares_directory(shares)

        # Return the share message
        return path_join([ciphertext, sig], separator="||")

    def receive_share(self, from_username, newname, message):
        # Obtain ciphertext and signature from message
        if "||" not in message: raise IntegrityError()
        msg_tokens = message.split("||")
        if len(msg_tokens) != 2: raise IntegrityError()
        ciphertext, sig = msg_tokens
        ciphertext_user = path_join([ciphertext, self.username], separator="/")
        # Verify message integrity
        verify_k = self.pks.get_signature_key(from_username)
        if verify_k is None: raise IntegrityError()
        if not self.crypto.asymmetric_verify(ciphertext_user, sig, verify_k):
            raise IntegrityError()
        # Decrypt ciphertext
        msg = self.crypto.asymmetric_decrypt(ciphertext, self.elg_priv_key)
        # Extract share node information
        msg = msg[len("[POINTER]"):]
        ke2, km2, did = msg.split("||")
        # Get symmetric keys
        ke, km, kn = self.get_symmetric_keys()
        # Get a new kid for receiver to store share node under NEWNAME 
        kid = self.get_kid(newname, kn)
        key_node_v = "[POINTER]{0}||{1}||{2}".format(ke2, km2, did) 
        key_node_v = self.encrypt_value_for_storage(kid, key_node_v, ke, km)
        self.storage_server.put(kid, key_node_v)

    def revoke(self, user, name):
        # Get shares directory
        shares = self.get_shares_directory()
        # Update information about shared node to the directory
        if name not in shares: return
        # Get symmetric keys
        ke, km, kn = self.get_symmetric_keys()
        # Get ID for the key node of file NAME
        kid = self.get_kid(name, kn)
        # Get Ke, Km, and did for data node
        res = self.resolve(kid, ke, km)
        if res is None: return
        _, _, did, node = res

        # Create new encryption and mac keys for data node
        ke_new, km_new, _ = self.new_symmetric_keys()

        # Obtain a copy of the original file NAME and Re-encrypt data node
        data_to_store_enc = self.encrypt_value_for_storage(did, node, ke_new, km_new)
        self.storage_server.put(did, data_to_store_enc)

        # Update key node for the file
        key_node_v = "[POINTER]{0}||{1}||{2}".format(ke_new, km_new, did) 
        key_node_v_enc = self.encrypt_value_for_storage(kid, key_node_v, ke, km)
        self.storage_server.put(kid, key_node_v_enc)

        # Remove user from shares directory
        removed = shares[name].pop(user)
        # # Delete user's file
        self.storage_server.delete(removed["did"])
        # Update shares directory
        self.put_shares_directory(shares)
        # Update all non-revoked user's ke2 and km2 on shared nodes
        for usr, keys in shares[name].items():
            share_node_v = "[POINTER]{0}||{1}||{2}".format(ke_new, km_new, did) 
            share_node_v_enc = self.encrypt_value_for_storage(keys['did'], share_node_v, keys['ke'], keys['km'])
            self.storage_server.put(keys['did'], share_node_v_enc)
        
    def new_symmetric_keys(self, SYMMETRIC_KEY_LENGTH=16):
        """
        Generate three NEW random symmetric keys ke, km, and kn
        where ke is for symmetric encryption, km is for MAC, and
        kn is for name confidentiality
        """
        # Generate symmetric keys
        ke = self.crypto.get_random_bytes(SYMMETRIC_KEY_LENGTH)
        km = self.crypto.get_random_bytes(SYMMETRIC_KEY_LENGTH)
        kn = self.crypto.get_random_bytes(SYMMETRIC_KEY_LENGTH)
        return ke, km, kn

    def get_symmetric_keys(self):
        """
        Return the three random symmetric keys ke, km, and kn stored
        for the current client USERNAME
        """
        return self.ke, self.km, self.kn

    def put_shares_directory(self, shares):
        """
        Update client USERNAME's shares directory to SHARES
        """
        # Cache for performance reasons
        self.shares = shares

        # Get symmetric keys
        ke, km, _ = self.get_symmetric_keys()
         # id of shares directory
        share_dir = "{0}/shares".format(self.username)
        assert type(shares) == dict, "shares directory must be type dictionary"
        # Serialize SHARES directory
        shares = json.dumps(shares)
        # Encryption of SHARES directory
        data_to_store = self.encrypt_value_for_storage(share_dir, shares, ke, km)
        # Store SHARES directory
        self.storage_server.put(share_dir, data_to_store)

    def get_shares_directory(self):
        """
        Return the SHARES directory for the current USERNAME client
        """
        return self.shares
        
    def get_asymmetric_keys(self):
        """Get asymmetric public keys"""
        encrypt_k = self.pks.get_encryption_key(self.username)
        verify_k = self.pks.get_signature_key(self.username)
        return (encrypt_k, self.elg_priv_key), (verify_k, self.rsa_priv_key)

    def hash(self, value):
        """Hash VALUE using SHA256 cryptographic hash function"""
        return self.crypto.cryptographic_hash(value, hash_name="SHA256")

    def new_did(self, DID_LENGTH=16):
        """
        Return a new random ID for any data node

        Format: data/r, where r is random bytes of DID_LENGTH length
        """
        uid = self.crypto.get_random_bytes(DID_LENGTH)
        return path_join(["data", uid], separator="/")

    def get_kid(self, filename, kn):
        """
        Return the ID for the key node of FILENAME using Kn symmetric key
        """
        filename = path_join([filename, kn], separator="||")
        r = self.hash(filename)
        return path_join([self.username, "keys", r], separator="/")

    def decrypt_values_at_id(self, uid, ke, km):
        """
        Return value stored at key or data node id UID, if any. Otherwise, None.
        """
        # Obtain Value at kid:  "IV || C : HMAC(Km, IV || C || NAME)"
        data_stored = self.storage_server.get(uid)
        if data_stored is None: return None
        # Verify data integrity
        if ":" not in data_stored: raise IntegrityError()
        IV_ciphertext, mac = data_stored.split(":")
        IV_ciphertext_name = path_join([IV_ciphertext, uid], separator="||")
        mac_true = self.crypto.message_authentication_code(IV_ciphertext_name, km, 
                    hash_name="SHA256")
        if mac != mac_true: raise IntegrityError()
        iv, ciphertext = IV_ciphertext.split("||")
        # value: "Ke' || Km' || did"
        value = self.crypto.symmetric_decrypt(ciphertext, ke, cipher_name="AES", 
                                            mode_name='CBC', iv=iv)
        return value

    def encrypt_value_for_storage(self, name, value, ke, km, IV_LENGTH=16):
        """
        Encrypt VALUE using AES-CBC mode with random IV of IV_LENGTH using 
        symmetric key KE to get ciphertext C = AES_CBC(Ke, VALUE).

        Return: 
            ciphertext: "IV || C : HMAC(Km, IV || C || NAME)"
        """
        # Generate IV
        iv  = self.crypto.get_random_bytes(IV_LENGTH)
        # Encryption of data
        ciphertext = self.crypto.symmetric_encrypt(value, ke, 
                    cipher_name="AES", mode_name='CBC', iv=iv)
        # Prepend IV to ciphertext
        IV_ciphertext = path_join([iv, ciphertext], separator="||")
        # MAC ciphertext of data value
        IV_ciphertext_name = path_join([IV_ciphertext, name], separator="||")
        mac = self.crypto.message_authentication_code(IV_ciphertext_name, km, 
                    hash_name="SHA256") 

        return path_join([IV_ciphertext, mac], separator=":")

    def is_data_node(self, value):
        prefix = "[DATA]"
        return type(value) == str and value[:len(prefix)] == prefix

    def parse_data_node(self, value):
        assert self.is_data_node(value), "must be a data node for parse_data_node"
        prefix = "[DATA]"
        return value[len(prefix):]

    def is_pointer_node(self, value):
        prefix = "[POINTER]"
        return type(value) == str and value[:len(prefix)] == prefix

    def parse_pointer_node(self, value):
        assert self.is_pointer_node(value), "must be a data node for parse_share_node"
        prefix = "[POINTER]"
        value = value[len(prefix):]
        if "||" not in value: raise IntegrityError()
        parsed = value.split("||")
        if len(parsed) != 3: raise IntegrityError()
        ke, km, did = parsed
        return ke, km, did

    def upload_updates(self, updates, ke, km):
        for uid, data in updates:
            if data is None:
                self.storage_server.delete(uid)
            else:
                value = "[DATA]{0}".format(data)
                value_enc = self.encrypt_value_for_storage(uid, value, ke, km)
                self.storage_server.put(uid, value_enc)

    def get_server_node(self, uid, ke, km, isData=False):
        res = self.resolve(uid, ke, km)
        if res is None: raise IntegrityError()
        _, _, _, server_root = res
        if not self.is_data_node(server_root): raise IntegrityError()
        if isData:
            return self.parse_data_node(server_root)
        else:
            return json.loads(self.parse_data_node(server_root))

    def server_data(self, node, uid, ke, km):
        data = ""
        
        tree = LocalMerkleTree(self.hash, uid)
        tree.hash = node["h"]
        tree.left = node["l"]
        tree.right = node["r"]
        tree.length = node["n"]

        if node["r"] is None:
            data = self.get_server_node(node["l"], ke, km, isData=True)

            if self.hash(data) != node["h"]:
                raise IntegrityError()

            tree.left = DataNote(data, self.hash)
            tree.left.uid = node["l"]
            return data, tree
        else:
            left_node =  self.get_server_node(node["l"], ke, km, isData=False)
            right_node = self.get_server_node(node["r"], ke, km, isData=False)

            if self.hash("{0}{1}".format(left_node["h"], right_node["h"])) != node["h"]:
                raise IntegrityError()
            
            tmp, tree.left = self.server_data(left_node, node["l"], ke, km)
            data += tmp


            tmp, tree.right = self.server_data(right_node, node["r"], ke, km)
            data += tmp

            return data, tree

    def delete_server_tree(self, uid, ke, km):
        node = self.get_server_node(uid, ke, km)
        self.storage_server.delete(uid)
        if node["r"] is None:
            self.storage_server.delete(node["l"])
        else:
            self.delete_server_tree(node["l"], ke, km)
            self.delete_server_tree(node["r"], ke, km)

class DataNote:

    def __init__(self, data, hash_fn, uid_gen=None):
        self.data = data
        self.hash_fn = hash_fn
        if uid_gen:
            self.uid = uid_gen()
        else:
            self.uid = None
        self.hash = hash_fn(data)
        self.length = len(data)

    def to_string(self):
        return "{0}".format(self.data)

    def all_nodes(self):
        return [(self.uid, self.to_string())]

    def copy(self, uids):
        n = DataNote(self.data, self.hash_fn)
        n.uid = uids.pop(0)
        return n, uids

    def all_uids(self):
        return [self.uid]

class LocalMerkleTree:

    def __init__(self, hash_fn, uid=None):
        self.hash_fn = hash_fn
        self.uid = uid

    def initialize(self, value, blocksize=512, uid_gen=None):
        self.length = len(value)
        if len(value) <= blocksize:
            self.left = DataNote(value, self.hash_fn, uid_gen=uid_gen)
            self.right = None
            self.hash = self.hash_fn(value)
            if self.uid is None and uid_gen:
                self.uid = uid_gen()
        else:
            N = int(ceil(len(value) / blocksize))
            split_idx = (N+1) // 2 * blocksize

            if self.uid is None and uid_gen:
                self.uid = uid_gen()

            self.left  = LocalMerkleTree(self.hash_fn)
            self.left.initialize(value[:split_idx], blocksize=blocksize, uid_gen=uid_gen)

            self.right = LocalMerkleTree(self.hash_fn)
            self.right.initialize(value[split_idx:], blocksize=blocksize, uid_gen=uid_gen)

            self.hash = self.hash_fn("{0}{1}".format(self.left.hash, self.right.hash))

    def update_uids(self, uids):
        if len(uids) == 0: return uids
        self.uid = uids.pop(0)
        if len(uids) == 0: return uids
        if type(self.left) == DataNote:
            self.left.uid = uids.pop(0)
        else:
            uids = self.left.update_uids(uids)
            uids = self.right.update_uids(uids)
        return uids

    def uid_gen(self):
        yield self.uid
        if type(self.left) == DataNote:
            yield self.left.uid
        else:
            for uid in self.left.uid_gen():
                yield uid
            for uid in self.right.uid_gen():
                yield uid

    def all_uids(self):
        return list(self.uid_gen())

    def copy(self, uids):
        root =  LocalMerkleTree(self.hash_fn)
        root.uid = uids.pop(0)
        root.length = self.length
        root.hash = self.hash
        root.left, uids = self.left.copy(uids)
        if self.right:
            root.right, uids = self.right.copy(uids)
        return root, uids

    def get_data(self):
        if type(self.left) == DataNote:
            return self.left.data
        else:
            return "{0}{1}".format(self.left.get_data(), self.right.get_data())

    def data_blocks(self):
        if type(self.left) == DataNote:
            return [self.left.data]
        else:
            return self.left.data_blocks() + self.right.data_blocks()

    def all_nodes(self):
        result = list()
        if type(self.left) == DataNote:
            result.append((self.left.uid, self.left.to_string()))
            result.append((self.uid, self.to_string()))
        else:
            result.append((self.uid, self.to_string()))
            result += self.left.all_nodes()
            result += self.right.all_nodes()
        return result

    def compare_and_update(self, tree):
        """
        Compare this merkle tree with TREE, updating this tree to be TREE along the way.
        
        Return a list of (uid, new_tree_string) that should be updated on server
        """
        errMsg = "can not compare LocalMerkleTree with {0}"
        assert type(tree) == LocalMerkleTree, errMsg.format(type(tree))

        errMsg = "can only compare tree with equal or smaller tree: {0} : {1}"
        assert self.length >= tree.length, errMsg.format(self.length, tree.length)

        changes = list()

        if type(self.left) == DataNote:
            if self.hash != tree.hash:
                self.left, _ = tree.left.copy(self.left.all_uids())
                self.hash = tree.hash
                if type(tree.left) != DataNote:
                    self.length = tree.length
                    self.right, _ = tree.right.copy(self.right.all_uids())
                    changes += tree.right.all_nodes()
                changes.append((self.uid, self.to_string()))
                changes.append((self.left.uid, self.left.to_string()))

        else:
            if self.hash != tree.hash:
                self.hash = tree.hash
                self.length = tree.length
                if type(tree.left) == DataNote:
                    self.left, _ = tree.left.copy(self.left.all_uids())
                    changes.append((self.left.uid, self.left.to_string()))
                    for u in self.right.all_uids():
                        changes.append((u, None))
                    self.right = None
                else:

                    if self.left.hash != tree.left.hash:
                        if self.left.length >= tree.left.length:
                            changes += self.left.compare_and_update(tree.left)
                        else:
                            self.left, _ = tree.left.copy(self.left.all_uids())
                            changes.append((self.left.uid, self.left.to_string()))
                            changes += self.left.all_nodes()
                    if self.right.hash != tree.right.hash:
                        if self.right.length >= tree.right.length:
                            changes += self.right.compare_and_update(tree.right)
                        else:
                            self.right, _ = tree.right.copy(self.right.all_uids())
                            changes.append((self.right.uid, self.right.to_string()))
                            changes += self.right.all_nodes()

                changes.append((self.uid, self.to_string()))
        return changes

    def to_string(self):
        if type(self.left) == DataNote:
            res = {
                "l": self.left.uid,
                "r": None,
                "n": self.length,
                "h": self.hash
            }
        else:
            res = {
                "l": self.left.uid,
                "r": self.right.uid,
                "n": self.length,
                "h": self.hash
            }

        return json.dumps(res)

'''
ciphertext-policy attribute-based encryption
:author: charm-crypto
:Date: 2023-11-14
'''

from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair, extract_key
#from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.msp import MSP
import os
import json

debug = False


class Waters11():

    def __init__(self):
        #ABEnc.__init__(self)
        #
        self.group = PairingGroup('SS512')
        self.uni_size = ['1','2','3','4','5','6','7','8','9','10','11','12','13','14','15']  # bound on the size of the universe of attributes
        self.util = MSP(self.group, False)

    def ser(self, bef_ser):
        return self.group.serialize(bef_ser)

    def deser(self, aft_ser):
        return self.group.deserialize(aft_ser)

    def setup(self):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('Setup algorithm:\n')

        # pick a random element each from two source groups and pair them
        g1 = self.group.random(G1)


        g2 = self.group.random(G2)
        alpha = self.group.random(ZR)
        g1_alpha = g1 ** alpha
        e_gg_alpha = pair(g1_alpha, g2)
        #print(type(g1))
        a = self.group.random(ZR)
        g1_a = g1 ** a

        h = {}
        for i in self.uni_size:
            h[i] = self.ser(self.group.random(G1))

        pk = {
            'g1': self.ser(g1),
            'g2': self.ser(g2),
            'g1_a': self.ser(g1_a),
            'h': h,
            'e_gg_alpha': self.ser(e_gg_alpha),
            'g1_alpha': self.ser(g1_alpha)
        }
        msk = {'g1_alpha': self.ser(g1_alpha)}
        return pk, msk

    def keygen(self, pk, msk, attr_list):
        """
        Generate a key for a set of attributes.
        """
        t = self.group.random(ZR)
        k0 = self.deser(msk['g1_alpha']) * (self.deser(pk['g1_a']) ** t)
        L = self.deser(pk['g2']) ** t

        K = {}
        for attr in attr_list:
            K[attr] = self.ser(self.deser(pk['h'][attr]) ** t)

        return {'attr_list': attr_list, 'k0': self.ser(k0), 'L': self.ser(L), 'K': K}

    def symmetric_encrypt(self, msg, dk):
        k = extract_key(dk)
        a = SymmetricCryptoAbstraction(k)
        c = a.encrypt(msg)
        return c
    def symmetric_decrypt(self, cipher, dk):
        k = extract_key(dk)
        a = SymmetricCryptoAbstraction(k)
        msg = a.decrypt(cipher)
        return msg

    def encrypt(self, pk, msg, policy_str):
        """
         Encrypt a message M under a monotone span program.
        """

        # Symmetric encryption key
        key = self.group.random(GT)
        #key = self.groupG.init(ZR, k)
        # enc(key)(msg)
        Encmsg = self.symmetric_encrypt(msg, key)

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # pick randomness
        u = []
        for i in range(num_cols):
            rand = self.group.random(ZR)
            u.append(rand)
        s = u[0]    # shared secret

        c0 = self.deser(pk['g2']) ** s

        C = {}
        D = {}
        for attr, row in mono_span_prog.items():
            cols = len(row)
            sum = 0
            for i in range(cols):
                sum += row[i] * u[i]
            attr_stripped = self.util.strip_index(attr)
            attr_stripped = str(attr_stripped)
            r_attr = self.group.random(ZR)
            c_attr = (self.deser(pk['g1_a']) ** sum) / (self.deser(pk['h'][attr_stripped]) ** r_attr)
            d_attr = self.deser(pk['g2']) ** r_attr
            attr = str(attr)
            C[attr] = self.ser(c_attr)
            D[attr] = self.ser(d_attr)

        c_m = (self.deser(pk['e_gg_alpha']) ** s) * key

        return {'c0': self.ser(c0), 'C': C, 'D': D, 'c_m': self.ser(c_m), 'Encmsg':Encmsg}, policy

    def decrypt(self, pk, ctxt, key, c_p):
        """
         Decrypt ciphertext ctxt with key.
        """

        if debug:
            print('Decryption algorithm:\n')
        policy = self.util.createPolicy(c_p)
        nodes = self.util.prune(policy, key['attr_list'])
        if not nodes:
            print ("Policy not satisfied.")
            return None

        prodG = 1
        prodGT = 1
        #print("temp:",key)
        ctxt = eval(ctxt)
        #key = eval(key)
        #print("ctxt:",type(ctxt))
        #print("c_p",c_p)
        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr = str(attr)
            attr_stripped = self.util.strip_index(attr)
            attr_stripped = str(attr_stripped)
            prodG *= self.deser(ctxt['C'][attr])
            prodGT *= pair(self.deser(key['K'][attr_stripped]), self.deser(ctxt['D'][attr]))
        dec_key = (self.deser(ctxt['c_m']) * pair(prodG, self.deser(key['L'])) * prodGT) / pair(self.deser(key['k0']), self.deser(ctxt['c0']))
        print("dec success:", self.symmetric_decrypt(ctxt['Encmsg'], dec_key).decode())
        return self.symmetric_decrypt(ctxt['Encmsg'], dec_key).decode()

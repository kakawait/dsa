package se.chalmers.cryptography.dsa;

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * User: kakawait <thibaud.lepretre@gmail.com>
 * Date: 17/11/11
 * Time: 16:34
 * To change this template use File | Settings | File Templates.
 */
public class DSA {
    private DSAUser DSAUsers;

    public DSA(BigInteger p, BigInteger q, BigInteger g) {
        this.DSAUsers = new DSAUser(p, q, g);
    }

    public DSA(BigInteger p, BigInteger q, BigInteger g, BigInteger x, BigInteger y) {
        this.DSAUsers = new DSAUser(p, q, g, x, y);
    }

    public BigInteger[][] generate(BigInteger n) {
        BigInteger[][] keys = new BigInteger[n.intValue()][];
        for (int i = 0; i < n.intValue(); i++) {
            BigInteger[] pair = new BigInteger[2];
            pair[0] = this.generateX();
            pair[1] = this.getG().modPow(pair[0], this.getP());
            keys[i] = pair;
        }

        return keys;
    }

    public BigInteger[] sign(String digestMessage) {
        BigInteger z = new BigInteger(digestMessage, 16);
        BigInteger k = this.generateK();
        BigInteger r = this.getG().modPow(k, this.getP()).mod(this.getQ());
        BigInteger s = (k.modInverse(this.getQ()).multiply(z.add(this.getX().multiply(r)))).mod(this.getQ());

        BigInteger[] signature = new BigInteger[2];
        signature[0] = r;
        signature[1] = s;

        return signature;
    }

    public boolean verify(BigInteger publicKey, String digestMessage, BigInteger r, BigInteger s) {
        if (r.compareTo(this.getQ()) >= 0 || r.compareTo(BigInteger.ZERO) <= 0) return false;
        if (s.compareTo(this.getQ()) >= 0 || s.compareTo(BigInteger.ZERO) <= 0) return false;

        BigInteger z = new BigInteger(digestMessage, 16);
        BigInteger w = s.modInverse(getQ());
        BigInteger u1 = z.multiply(w).mod(getQ());
        BigInteger u2 = r.multiply(w).mod(getQ());
        BigInteger v = ((this.getG().modPow(u1, this.getP())
                .multiply(publicKey.modPow(u2, this.getP()))).mod(this.getP())).mod(this.getQ());

        return v.compareTo(r) == 0;
    }

    public BigInteger generateX() {
        SecureRandom r = new SecureRandom();
        BigInteger x;
        do {
            x = new BigInteger(getQ().bitLength(), r);
        } while ((this.getQ().compareTo(x) < 1) || (x.compareTo(BigInteger.ZERO) < 1));

        return x;
    }

    public BigInteger generateK() {
        SecureRandom r = new SecureRandom();
        BigInteger k;
        do {
            k = new BigInteger(getQ().bitLength(), r);
        } while ((this.getQ().compareTo(k) < 1) || (k.compareTo(BigInteger.ZERO) < 1));

        return k;
    }

    public BigInteger getP() {
        return this.DSAUsers.getP();
    }

    public BigInteger getQ() {
        return this.DSAUsers.getQ();
    }

    public BigInteger getG() {
        return this.DSAUsers.getG();
    }

    public BigInteger getX() {
        return this.DSAUsers.getX();
    }

    public void setX(BigInteger x) {
        this.DSAUsers.setX(x);
    }

    public BigInteger getY() {
        return this.DSAUsers.getY();
    }

    public void setY(BigInteger y) {
        this.DSAUsers.setY(y);
    }
}

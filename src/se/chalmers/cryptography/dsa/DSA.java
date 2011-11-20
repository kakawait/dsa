package se.chalmers.cryptography.dsa;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * User: Thibaud Leprêtre <thibaud.lepretre@gmail.com>, Nicolas hubert <hubertn@efrei.fr>
 * Date: 20/11/11
 * Time: 18:34
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
            pair[1] = this.getG().modPow(pair[0], this.getP()); // y = g^x mod p
            keys[i] = pair;
        }

        return keys;
    }

    public BigInteger[] sign(String digestMessage) {
        BigInteger z = new BigInteger(digestMessage, 16); // cast hex digestMessage in BigInteger with 16 is the radix
        BigInteger k = this.generateK();
        BigInteger r = this.getG().modPow(k, this.getP()).mod(this.getQ()); // r = (g^k mod p) mod q
        BigInteger s = (k.modInverse(this.getQ()).multiply(z.add(this.getX().multiply(r)))).mod(this.getQ()); // (k^−1 (z + xr)) mod q

        BigInteger[] signature = new BigInteger[2];
        signature[1] = s;
        signature[0] = r;

        return signature;
    }

    public boolean verify(BigInteger publicKey, String digestMessage, BigInteger r, BigInteger s) {
        if (r.compareTo(this.getQ()) >= 0 || r.compareTo(BigInteger.ZERO) <= 0) return false; // verify that r is not equal to 0 and < q
        if (s.compareTo(this.getQ()) >= 0 || s.compareTo(BigInteger.ZERO) <= 0) return false; // verify that s is not equal to 0 and < q

        BigInteger z = new BigInteger(digestMessage, 16); // cast hex digestMessage in BigInteger with 16 is the radix
        BigInteger w = s.modInverse(getQ()); // (s′)^–1 mod q
        BigInteger u1 = z.multiply(w).mod(getQ()); //(zw) mod q
        BigInteger u2 = r.multiply(w).mod(getQ()); // ((r′)w) mod q
        BigInteger v = ((this.getG().modPow(u1, this.getP())
                .multiply(publicKey.modPow(u2, this.getP()))).mod(this.getP())).mod(this.getQ()); // (((g)^u1 (y)^u2) mod p) mod q

        return v.compareTo(r) == 0; // compare v and r to verify the signature
    }

    public BigInteger generateX() {
        SecureRandom r = new SecureRandom();
        BigInteger x;
        do {
            x = new BigInteger(getQ().bitLength(), r);
        } while ((this.getQ().compareTo(x) < 1) || (x.compareTo(BigInteger.ZERO) < 1));
		//verify that the number is chosen at random in the interval 0 < x < q
        return x;
    }

    public BigInteger generateK() {
        SecureRandom r = new SecureRandom();
        BigInteger k;
        do {
            k = new BigInteger(getQ().bitLength(), r);
        } while ((this.getQ().compareTo(k) < 1) || (k.compareTo(BigInteger.ZERO) < 1));
		//verify that the number is chosen at random in the interval 0 < k < q
        return k;
    }
	
	//Definitions of the getters and setters
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
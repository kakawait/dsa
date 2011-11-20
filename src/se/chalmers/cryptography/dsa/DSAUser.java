package se.chalmers.cryptography.dsa;

import java.math.BigInteger;

/**
 * User: Thibaud Leprêtre <thibaud.lepretre@gmail.com>, Nicolas hubert <hubertn@efrei.fr>
 * Date: 20/11/11
 * Time: 18:14
 */
public class DSAUser {
    public final static int P_BIT_LENGTH = 1024; //set the length of p
    public final static int Q_BIT_LENGTH = 160;  //set the length of q

    private BigInteger[] domainParameters = new BigInteger[3]; //table containing p, q, g
    private BigInteger publicKey = null;
    private BigInteger privateKey = null;

    public static boolean check(BigInteger p, BigInteger q, BigInteger g) {
        if (g.compareTo(BigInteger.ONE) <= 0) return false;
        if (p.bitLength() != P_BIT_LENGTH) return false; // verify that p is a 1024 bit number
        if (q.bitLength() != Q_BIT_LENGTH) return false; // verify that q a 160 bit number

        BigInteger pMinusOne = p.subtract(BigInteger.ONE);
        if (pMinusOne.remainder(q).compareTo(BigInteger.ZERO) != 0) return false; // verify that q is a divisor of p-1;

        if (g.modPow(q, p).compareTo(BigInteger.ONE) != 0) return false; // verify that g has order q i.e. gq mod p = 1 and g > 1

        if (!p.isProbablePrime(20)) return false; // verify that p is a prime number
        if (!q.isProbablePrime(20)) return false; // verify that q is a prime number

        return true;
    }

	//Definitions of both constructors
    public DSAUser(BigInteger p, BigInteger q, BigInteger g) {
        this.domainParameters[0] = p;
        this.domainParameters[1] = q;
        this.domainParameters[2] = g;
    }

    public DSAUser(BigInteger p, BigInteger q, BigInteger g, BigInteger x, BigInteger y) {
        this.domainParameters[0] = p;
        this.domainParameters[1] = q;
        this.domainParameters[2] = g;
        this.privateKey = x;
        this.publicKey = y;
    }

	//Definitions of the getters and setters
    public BigInteger getP() {
        return domainParameters[0];
    }

    public BigInteger getQ() {
        return domainParameters[1];
    }

    public BigInteger getG() {
        return domainParameters[2];
    }

    public BigInteger getX() {
        return this.privateKey;
    }

    public void setX(BigInteger x) {
        this.privateKey = x;
    }

    public BigInteger getY() {
        return this.publicKey;
    }

    public void setY(BigInteger y) {
        this.publicKey = y;
    }
}

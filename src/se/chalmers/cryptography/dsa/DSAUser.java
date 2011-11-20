package se.chalmers.cryptography.dsa;

import java.math.BigInteger;

/**
 * User: Thibaud Leprêtre <thibaud.lepretre@gmail.com>
 * Date: 18/11/11
 * Time: 10:14
 */
public class DSAUser {
    public final static int P_BIT_LENGTH = 1024;
    public final static int Q_BIT_LENGTH = 160;

    private BigInteger[] domainParameters = new BigInteger[3];
    private BigInteger publicKey = null;
    private BigInteger privateKey = null;

    public static boolean check(BigInteger p, BigInteger q, BigInteger g) {
        if (g.compareTo(BigInteger.ONE) <= 0) return false;
        if (p.bitLength() != P_BIT_LENGTH) return false;
        if (q.bitLength() != Q_BIT_LENGTH) return false;

        BigInteger pMinusOne = p.subtract(BigInteger.ONE);
        if (pMinusOne.remainder(q).compareTo(BigInteger.ZERO) != 0) return false;

        if (g.modPow(q, p).compareTo(BigInteger.ONE) != 0) return false;

        if (!p.isProbablePrime(20)) return false;
        if (!q.isProbablePrime(20)) return false;

        return true;
    }

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

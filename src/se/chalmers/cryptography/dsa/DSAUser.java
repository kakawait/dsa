package se.chalmers.cryptography.dsa;

import java.math.BigInteger;

/**
 * User: kakawait <thibaud.lepretre@gmail.com>
 * Date: 18/11/11
 * Time: 10:14
 * To change this template use File | Settings | File Templates.
 */
public class DSAUser {
    private final int P_BIT_LENGTH = 1024;
    private final int Q_BIT_LENGTH = 160;

    private BigInteger[] domainParameters = new BigInteger[3];
    private BigInteger publicKey = null;
    private BigInteger privateKey = null;

    public DSAUser(BigInteger p, BigInteger q, BigInteger g) {
        this.domainParameters[0] = p;
        this.domainParameters[1] = q;
        this.domainParameters[2] = g;
    }

    public DSAUser(BigInteger p, BigInteger q, BigInteger g, BigInteger x, BigInteger y) {
        this.domainParameters[0] = p;
        this.domainParameters[1] = q;
        this.domainParameters[2] = g;
        this.publicKey = x;
        this.privateKey = y;
    }

    private boolean check(BigInteger p, BigInteger q, BigInteger g) {
        if (p.bitLength() != this.P_BIT_LENGTH) return false;
        if (q.bitLength() != this.Q_BIT_LENGTH) return false;

        for (int i = 0; i <= 8 ; i++) {
            if (!p.isProbablePrime(10000)) {
                return false;
            }
            if (!q.isProbablePrime(10000)) {
                return false;
            }
        }

        return true;

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
        return this.publicKey;
    }

    public BigInteger getY() {
        return this.privateKey;
    }
}

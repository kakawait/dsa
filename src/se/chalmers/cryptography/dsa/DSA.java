package se.chalmers.cryptography.dsa;

/**
 * User: Thibaud Leprêtre
 * Date: 17/11/11
 * Time: 16:34
 * To change this template use File | Settings | File Templates.
 */

import java.math.BigInteger;
import java.security.SecureRandom;

public class DSA {
    private final int Q_BIT_LENGTH = 160;

    private BigInteger[] domainParameters = new BigInteger[3];
    private BigInteger publicKey;
    private BigInteger privateKey;

    public DSA(BigInteger p, BigInteger q, BigInteger g, BigInteger x, BigInteger y) {
        this.domainParameters[0] = p;
        this.domainParameters[1] = q;
        this.domainParameters[2] = g;
        this.publicKey = x;
        this.privateKey = y;
    }

    public BigInteger[] sign(String digestMessage) {
        BigInteger z = new BigInteger(digestMessage.getBytes());
        BigInteger k = this.generateK();
        BigInteger r = this.getG().modPow(k, this.getP()).mod(this.getQ());
        BigInteger s = (k.modInverse(getQ()).multiply(z.add(getX().multiply(r)))).mod(getQ());

        BigInteger[] signature = new BigInteger[2];
        signature[0] = r;
        signature[1] = s;
        return signature;
    }

    public boolean verify(BigInteger privateKey, String digestMessage, BigInteger r, BigInteger s) {
        if(r.compareTo(this.getQ()) >= 0 || r.compareTo(BigInteger.ZERO) <= 0) return false;
        if(s.compareTo(this.getQ()) >= 0 || s.compareTo(BigInteger.ZERO) <= 0) return false;

        BigInteger z = new BigInteger(digestMessage.getBytes());
        BigInteger w = s.modInverse(getQ());
        BigInteger u1 = z.multiply(w).mod(getQ());
        BigInteger u2 = r.multiply(w).mod(getQ());
        BigInteger v = ((getG().modPow(u1, getP()).multiply(privateKey.modPow(u2, getP()))).mod(getP())).mod(getQ());

        return v.compareTo(r) == 0;
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

    public static void main(String[] args) {
        DSA dsa = new DSA(
                new BigInteger("102865584259843077175583195011997798900482038016705824136288380475734860009055428071534495956844807748416572686838253895244634687898659646424515259679129905513743899853971066468883670407530107234961085482225328667572772611162756643027105617873895021996158552984843708233824989792811721408577351617080369547993"),
                new BigInteger("734415599462729831694143846331445277609193755927"),
                new BigInteger("63615006880335642768473038477258757436464860136916565207798584167060621564899979263408565137993978149206751054438974059615983337126379668370747907507911540381031959187353048278562320341063050939775344313271013777131358834376209974551749493023310606751625276738876397935042130121966817767949476523717161640453"),
                new BigInteger("339119201894965867922409227633199021527378715543"),
                new BigInteger("1099906791313925528746008054081768734007884349815325963667520491768596235922636596649198172987598573083011790017146356061273962023338014420645127092468263770753970716461208880423045761205934804880887634821616587683235765408867072852094816664326084550730344050243082288308837441908172297994552279650972016922")
        );
        BigInteger[] signature = new BigInteger[2];
        signature = dsa.sign("10B4D55F2376DBA00CE4A6AE2B122E9554035EF2");
        System.out.println(signature[0]);
        System.out.println(signature[1]);
        boolean verify = dsa.verify(
                new BigInteger("1099906791313925528746008054081768734007884349815325963667520491768596235922636596649198172987598573083011790017146356061273962023338014420645127092468263770753970716461208880423045761205934804880887634821616587683235765408867072852094816664326084550730344050243082288308837441908172297994552279650972016922"),
                "10B4D55F2376DBA00CE4A6AE2B122E9554035EF2",
                signature[0],
                signature[1]
        );
        System.out.println(verify);
    }
}

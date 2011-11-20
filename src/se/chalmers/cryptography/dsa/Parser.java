package se.chalmers.cryptography.dsa;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.ArrayList;

/**
 * User: Thibaud Leprêtre <thibaud.lepretre@gmail.com>
 * Date: 18/11/11
 * Time: 11:35
 * Parser works thanks to try/catch/finally statements. The principle is simple, if some parameters are
 * wrong I just throw a new exception. When exception is catch I display "invalid_group".
 * Moreover I use the standard input so in order to launch the program you have to do:
 *      - dsa.jar < file.txt
 *      - file.txt | dsa.jar
 * Regarding the validation, I check:
 *      - the parameter's order, p=39293.. then q=3892.. then g=3992...
 *      - p, q and g must be a numeric value => /^[0-9]+$/
 *      - use of DSAUser.check function that valid p, q and g
 *      - test D to be a 40 char length with just number or letter => /^[0-9A-Za-z]{40}$/
 *      - plus some other tests...
 */
public class Parser {
    public static void main(String[] args) throws Exception {
        BufferedReader in = null;
        try {
            in = new BufferedReader(new InputStreamReader(System.in));
            String line;

            String[] domainParameters = new String[3];
            domainParameters[0] = (in.readLine().split("^p="))[1];
            domainParameters[1] = (in.readLine().split("^q="))[1];
            domainParameters[2] = (in.readLine().split("^g="))[1];

            System.out.println("p=" + domainParameters[0]);
            System.out.println("q=" + domainParameters[1]);
            System.out.println("g=" + domainParameters[2]);

            for (String domainParameter : domainParameters) {
                if (!domainParameter.matches("^[0-9]+$")) throw new Exception();
            }
            BigInteger p = new BigInteger(domainParameters[0]);
            BigInteger q = new BigInteger(domainParameters[1]);
            BigInteger g = new BigInteger(domainParameters[2]);
            if (!DSAUser.check(p, q, g)) throw new Exception();

            DSA dsa = new DSA(p, q, g);

            String action = in.readLine();
            if (action.equals("genkey")) {
                String n = (in.readLine().split("^n="))[1];
                if (!n.matches("^[0-9]+$")) throw new Exception();
                System.out.println("valid_group");
                for (BigInteger[] pair : dsa.generate(new BigInteger(n))) {
                    System.out.println("x=" + pair[0]);
                    System.out.println("y=" + pair[1]);
                }
            } else if (action.equals("sign")) {
                String x = (in.readLine().split("^x="))[1];
                String y = (in.readLine().split("^y="))[1];
                if (!x.matches("^[0-9]+$") || !y.matches("^[0-9]+$")) throw new Exception();
                ArrayList<String> d = new ArrayList<String>();
                while ((line = in.readLine()) != null) {
                    d.add(line.split("^D=")[1]);
                    if (!d.get(d.size() - 1).matches("^[0-9A-Za-z]{40}$")) throw new Exception();
                }
                dsa.setX(new BigInteger(x));
                dsa.setY(new BigInteger(y));
                System.out.println("valid_group");
                for (String digestMessage : d) {
                    BigInteger[] signature = dsa.sign(digestMessage);
                    System.out.println("r=" + signature[0]);
                    System.out.println("s=" + signature[1]);
                }
            } else if (action.equals("verify")) {
                String y = (in.readLine().split("^y="))[1];
                if (!y.matches("^[0-9]+$")) throw new Exception();
                boolean eof = false;
                while (!eof) {
                    line = in.readLine();
                    if (line != null) {
                        String d = (line.split("^D="))[1];
                        String r = (in.readLine().split("^r="))[1];
                        String s = (in.readLine().split("^s="))[1];

                        if (dsa.verify(new BigInteger(y), d, new BigInteger(r), new BigInteger(s))) {
                            System.out.println("signature_valid");
                        } else {
                            System.out.println("signature_invalid");
                        }
                    } else {
                        eof = true;
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("invalid_group");
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }
}

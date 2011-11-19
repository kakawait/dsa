package se.chalmers.cryptography.dsa;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.ArrayList;

/**
 * User: kakawait <thibaud.lepretre@gmail.com>
 * Date: 18/11/11
 * Time: 11:35
 * To change this template use File | Settings | File Templates.
 */
public class Parser {
    public static void main(String[] args) throws Exception {
        /*DSA dsa = new DSA(
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
                "C1CBB20237CF8C5F58F3302C91DDE80388C3A7D5",
                signature[0],
                signature[1]
        );
        System.out.println(verify); */

        BufferedReader in = null;
        try {
            in = new BufferedReader(new InputStreamReader(System.in));
            String line;

            String[] domainParameters = new String[3];

            domainParameters[0] = (in.readLine().split("^p="))[1];
            domainParameters[1] = (in.readLine().split("^q="))[1];
            domainParameters[2] = (in.readLine().split("^g="))[1];

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
                    if (!d.get(d.size() - 1).matches("^[0-9A-Za-z]+$")) throw new Exception();
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

            }


            System.exit(0);
            while ((line = in.readLine()) != null) {
                System.out.println(line);
            }
        } catch (Exception e) {
            throw e;
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }
}

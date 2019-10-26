package com.cryptopals;

import com.cryptopals.set_5.DiffieHellmanHelper;
import com.cryptopals.set_5.RSAHelper;
import com.cryptopals.set_6.DSAHelper;
import com.cryptopals.set_6.RSAHelperExt;
import com.cryptopals.set_8.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.cryptopals.Set8.CHALLENGE56_MSG;
import static com.cryptopals.Set8.CURVE_25519_ORDER;
import static com.cryptopals.Set8.CURVE_25519_PRIME;
import static java.math.BigInteger.ZERO;
import static java.math.BigInteger.ONE;
import static java.math.BigInteger.valueOf;
import static org.junit.jupiter.api.Assertions.*;

class Set8Tests {

    @DisplayName("https://toadstyle.org/cryptopals/57.txt")
    @ParameterizedTest @ValueSource(strings = { "rmi://localhost/DiffieHellmanBobService" })
    // The corresponding SpringBoot server application must be running.
    void challenge57(String url) throws RemoteException, NotBoundException, MalformedURLException,
            NoSuchAlgorithmException, InvalidKeyException{

        // First check the implementation of Garner's algorithm for correctness
        BigInteger   test[][] = {
                {  BigInteger.valueOf(2),  BigInteger.valueOf(5) },
                {  BigInteger.valueOf(1),  BigInteger.valueOf(7) },
                {  BigInteger.valueOf(3),  BigInteger.valueOf(11) },
                {  BigInteger.valueOf(8),  BigInteger.valueOf(13) },
        };
        assertEquals(BigInteger.valueOf(2192), Set8.garnersAlgorithm(Arrays.asList(test)));

        // Now check the whole implementation
        BigInteger b = Set8.breakChallenge57(url);
        DiffieHellman bob = (DiffieHellman) Naming.lookup(url);
        assertTrue(bob.isValidPrivateKey(b));
    }

    @DisplayName("Pollard's kangaroo algorithm")
    @Test
    void challenge58PollardsKangaroo() {
        // First check the implementation of J.M. Pollard's algorithm for correctness
        DiffieHellmanHelper dh = new DiffieHellmanHelper(
                new BigInteger("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623"),
                new BigInteger("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357"));

        BigInteger   y = new BigInteger("7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119"),
                b = dh.dlog(y, BigInteger.valueOf(2).pow(20), DiffieHellmanHelper::f);
        assertEquals(dh.getGenerator().modPow(b, dh.getModulus()), y);

        y = new BigInteger("9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733");
        b = dh.dlog(y, BigInteger.valueOf(2).pow(40), DiffieHellmanHelper::f);
        assertEquals(dh.getGenerator().modPow(b, dh.getModulus()), y);
    }

    @DisplayName("https://toadstyle.org/cryptopals/58.txt")
    @ParameterizedTest @ValueSource(strings = { "rmi://localhost/DiffieHellmanBobService" })
    // The corresponding SpringBoot server application must be running.
    void challenge58(String url) throws RemoteException, NotBoundException, MalformedURLException,
            NoSuchAlgorithmException, InvalidKeyException{
        BigInteger   b = Set8.breakChallenge58(url);
        DiffieHellman bob = (DiffieHellman) Naming.lookup(url);
        assertTrue(bob.isValidPrivateKey(b));
    }

    @DisplayName("WeierstrassFormECCurve")
    @Test
    void challenge59WeierstrassFormECCurve() {
        WeierstrassECGroup group = new WeierstrassECGroup(new BigInteger("233970423115425145524320034830162017933"),
                valueOf(-95051), valueOf(11279326), new BigInteger("233970423115425145498902418297807005944"));
        WeierstrassECGroup.ECGroupElement   base = group.createPoint(
                valueOf(182), new BigInteger("85518893674295321206118380980485522083"));
        BigInteger   q = new BigInteger("29246302889428143187362802287225875743");
        assertTrue(group.containsPoint(base));
        assertEquals(group.O, base.scale(q));
    }

    @DisplayName("https://toadstyle.org/cryptopals/59.txt")
    @ParameterizedTest @ValueSource(strings = { "rmi://localhost/ECDiffieHellmanBobService" })
        // The corresponding SpringBoot server application must be running.
    void challenge59(String url) throws RemoteException, NotBoundException, MalformedURLException,
            NoSuchAlgorithmException, InvalidKeyException {
        WeierstrassECGroup group = new WeierstrassECGroup(new BigInteger("233970423115425145524320034830162017933"),
                valueOf(-95051), valueOf(11279326), new BigInteger("233970423115425145498902418297807005944"));
        WeierstrassECGroup.ECGroupElement   base = group.createPoint(
                valueOf(182), new BigInteger("85518893674295321206118380980485522083"));
        BigInteger   q = new BigInteger("29246302889428143187362802287225875743");
        BigInteger   b = Set8.breakChallenge59(base, q, url);
        ECDiffieHellman bob = (ECDiffieHellman) Naming.lookup(url);
        assertTrue(bob.isValidPrivateKey(b));
    }

    @DisplayName("MontgomeryFormECCurve")
    @Test
    void challenge60MontgomeryFormECCurve() {
        MontgomeryECGroup group = new MontgomeryECGroup(new BigInteger("233970423115425145524320034830162017933"),
                valueOf(534), ONE, new BigInteger("233970423115425145498902418297807005944"));
        MontgomeryECGroup.ECGroupElement base = group.createPoint(
                valueOf(4), new BigInteger("85518893674295321206118380980485522083"));
        BigInteger   q = new BigInteger("29246302889428143187362802287225875743");
        assertTrue(group.containsPoint(base));
        assertEquals(group.O, base.scale(q));
        assertEquals(ZERO, base.ladder(q));
    }

    @DisplayName("Pollard's kangaroo algorithm on elliptic curve groups")
    @Test
    void challenge60PollardsKangaroo() {
        MontgomeryECGroup   mgroup = new MontgomeryECGroup(new BigInteger("233970423115425145524320034830162017933"),
                valueOf(534), ONE, new BigInteger("233970423115425145498902418297807005944"));
        MontgomeryECGroup.ECGroupElement   mbase = mgroup.createPoint(
                valueOf(4), new BigInteger("85518893674295321206118380980485522083"));
        BigInteger   exponent = valueOf(12130);
        assertEquals(exponent, mbase.dlog(mbase.scale(exponent), valueOf(1110000), ECGroupElement::f));
    }

    @DisplayName("https://toadstyle.org/cryptopals/61.txt")
    @Test
    void challenge61ECDSA() {
        MontgomeryECGroup   curve25519 = new MontgomeryECGroup(CURVE_25519_PRIME,
                valueOf(486662), ONE, CURVE_25519_ORDER.shiftRight(3), CURVE_25519_ORDER);
        MontgomeryECGroup.ECGroupElement   curve25519Base = curve25519.createPoint(
                valueOf(9), curve25519.mapToY(valueOf(9)));
        BigInteger   q = curve25519.getCyclicOrder();
        ECDSA   ecdsa = new ECDSA(curve25519Base, q);
        DSAHelper.Signature   signature = ecdsa.sign(CHALLENGE56_MSG.getBytes());
        ECDSA.PublicKey   legitPk = ecdsa.getPublicKey(),
                forgedPk = Set8.breakChallenge61ECDSA(CHALLENGE56_MSG.getBytes(), signature, ecdsa.getPublicKey());
        assertTrue(legitPk.verifySignature(CHALLENGE56_MSG.getBytes(), signature));
        assertTrue(forgedPk.verifySignature(CHALLENGE56_MSG.getBytes(), signature));
        assertNotEquals(legitPk, forgedPk);
    }

    @DisplayName("https://toadstyle.org/cryptopals/61.txt")
    @Test
    void challenge61RSA() {
        RSAHelperExt rsa = new RSAHelperExt(RSAHelper.PUBLIC_EXPONENT, 160);
        BigInteger rsaSignature = rsa.sign(CHALLENGE56_MSG.getBytes(), RSAHelperExt.HashMethod.SHA1);

        RSAHelper.PublicKey legitRSAPk = rsa.getPublicKey(),
                forgedRSAPk = Set8.breakChallenge61RSA(CHALLENGE56_MSG.getBytes(), rsaSignature,
                                                       legitRSAPk.getModulus().bitLength());

        assertTrue(legitRSAPk.verify(CHALLENGE56_MSG.getBytes(), rsaSignature));
        assertTrue(forgedRSAPk.verify(CHALLENGE56_MSG.getBytes(), rsaSignature));
    }

    @DisplayName("https://toadstyle.org/cryptopals/61.txt")
    @Test
    void challenge61RSAPrecomputedPrimes() {
        RSAHelperExt rsa = new RSAHelperExt(new BigInteger("1244531015222089066686014345871128487293834311511"),
                new BigInteger("1203007175264872213635758749034760908717988390329"), RSAHelper.PUBLIC_EXPONENT);
        BigInteger rsaSignature = rsa.sign(CHALLENGE56_MSG.getBytes(), RSAHelperExt.HashMethod.SHA1);

        DiffieHellmanUtils.PrimeAndFactors pq[] = new DiffieHellmanUtils.PrimeAndFactors[]{
                new DiffieHellmanUtils.PrimeAndFactors(
                        new BigInteger("2252226720431925817465020447075111488063403846689"),
                        Stream.of(2, 7, 277, 647, 2039, 2953, 14633, 139123, 479387, 904847).map(BigInteger::valueOf).collect(Collectors.toList())
                ),
                new DiffieHellmanUtils.PrimeAndFactors(
                        new BigInteger("2713856776699319359494147955700110393372009838087"),
                        Stream.of(2, 13, 17, 23, 26141, 56633, 80429, 241567, 652429, 1049941).map(BigInteger::valueOf).collect(Collectors.toList())
                ),
        };

        RSAHelper.PublicKey legitRSAPk = rsa.getPublicKey(),
                            forgedRSAPk = Set8.breakChallenge61RSA(CHALLENGE56_MSG.getBytes(), rsaSignature, pq,
                                                                   legitRSAPk.getModulus().bitLength());
        assertTrue(legitRSAPk.verify(CHALLENGE56_MSG.getBytes(), rsaSignature));
        assertTrue(forgedRSAPk.verify(CHALLENGE56_MSG.getBytes(), rsaSignature));
    }
}

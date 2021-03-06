package com.cryptopals.set_8;

import java.math.BigInteger;

/**
 * Represents an element of an ordered finite field. Implementing classes must be immutable.
 */
public interface FiniteFieldElement extends Comparable<FiniteFieldElement> {
    /** @return  an object of the implementing class. */
    FiniteFieldElement  add(FiniteFieldElement e);
    /** @return  an object of the implementing class. */
    FiniteFieldElement  subtract(FiniteFieldElement e);
    /**
     * Computes this + this + ... + this {@code k} times
     * @return  an object of the implementing class.
     */
    FiniteFieldElement  times(BigInteger k);
    /** @return  an object of the implementing class. */
    FiniteFieldElement  multiply(FiniteFieldElement e);
    /** @return  an object of the implementing class. */
    FiniteFieldElement  modInverse();
    /**
     * Computes this * this * ... * this {@code k} times, i.e. computes this<sup>k</sup>
     * @return  an object of the implementing class.
     */
    FiniteFieldElement  scale(BigInteger k);
    /** @return  an object of the implementing class. */
    FiniteFieldElement  getAdditiveIdentity();
    /** @return  an object of the implementing class. */
    FiniteFieldElement  getMultiplicativeIdentity();
    /** @return  an uniformly distributed element of the implementing class. */
    FiniteFieldElement getRandomElement();
    BigInteger  getOrder();
    BigInteger  getCharacteristic();
}

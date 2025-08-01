package com.zxl.cypto.provider;

import com.zxl.cypto.rsa.NativeRsa2;
import com.zxl.cypto.rsa.NativeRsa3;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class OpenSSLRSAGenerator extends KeyPairGeneratorSpi {

    private int keySize = 2048;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        this.keySize = keysize;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) {
        throw new UnsupportedOperationException("ParameterSpec initialization not supported");
    }

    @Override
    public KeyPair generateKeyPair() {
        return NativeRsa2.generateKeyPair(keySize);
    }
//    @Override
//    public KeyPair generateKeyPair() {
//        return NativeRsa3.generateKeyPair();
//    }
}

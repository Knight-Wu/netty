/*
 * Copyright 2018 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.handler.ssl;

import io.netty.buffer.ByteBufAllocator;
import io.netty.internal.tcnative.SSL;

import javax.net.ssl.X509KeyManager;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static io.netty.handler.ssl.ReferenceCountedOpenSslContext.toBIO;

class OpenSslKeyMaterialProvider {

    private final X509KeyManager keyManager;
    private final String password;

    OpenSslKeyMaterialProvider(X509KeyManager keyManager, String password) {
        this.keyManager = keyManager;
        this.password = password;
    }

    X509KeyManager keyManager() {
        return keyManager;
    }

    OpenSslKeyMaterial chooseKeyMaterial(ByteBufAllocator allocator, String alias) throws Exception {
        X509Certificate[] certificates = keyManager.getCertificateChain(alias);
        if (certificates == null || certificates.length == 0) {
            return null;
        }

        PrivateKey key = keyManager.getPrivateKey(alias);
        PemEncoded encoded = PemX509Certificate.toPEM(allocator, true, certificates);
        long chainBio = 0;
        long pkeyBio = 0;
        long chain = 0;
        long pkey = 0;
        try {
            chainBio = toBIO(allocator, encoded.retain());
            pkeyBio = toBIO(allocator, key);
            chain = SSL.parseX509Chain(chainBio);
            pkey = key == null ? 0 : SSL.parsePrivateKey(pkeyBio, password);
            OpenSslKeyMaterial keyMaterial = new OpenSslKeyMaterial(chain, pkey);
            chain = 0;
            pkey = 0;
            return keyMaterial;
        } finally {
            SSL.freeBIO(chainBio);
            SSL.freeBIO(pkeyBio);
            SSL.freeX509Chain(chain);
            SSL.freePrivateKey(pkey);
            encoded.release();
        }
    }

    void destroy() {
        // NOOP.
    }
}


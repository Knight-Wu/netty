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

import javax.net.ssl.X509KeyManager;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

final class OpenSslCachingKeyMaterialProvider extends OpenSslKeyMaterialProvider {

    private final ConcurrentMap<String, OpenSslKeyMaterial> cache = new ConcurrentHashMap<String, OpenSslKeyMaterial>();

    OpenSslCachingKeyMaterialProvider(X509KeyManager keyManager, String password) {
        super(keyManager, password);
    }

    @Override
    OpenSslKeyMaterial chooseKeyMaterial(ByteBufAllocator allocator, String alias) throws Exception {
        OpenSslKeyMaterial material = cache.get(alias);
        if (material == null) {
            material = super.chooseKeyMaterial(allocator, alias);
            if (material == null) {
                return null;
            }

            OpenSslKeyMaterial old = cache.putIfAbsent(alias, material);
            if (old != null) {
                material.release();
                material = old;
            }
        }
        return material.retain();
    }

    @Override
    void destroy() {
        for (OpenSslKeyMaterial material : cache.values()) {
            material.release();
        }
        cache.clear();
    }
}

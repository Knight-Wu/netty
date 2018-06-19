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

import io.netty.internal.tcnative.SSL;
import io.netty.util.AbstractReferenceCounted;
import io.netty.util.IllegalReferenceCountException;

final class OpenSslKeyMaterial extends AbstractReferenceCounted {

    private long chain;
    private long privateKey;

    OpenSslKeyMaterial(long chain, long privateKey) {
        this.chain = chain;
        this.privateKey = privateKey;
    }

    public long chain() {
        if (refCnt() <= 0) {
            throw new IllegalReferenceCountException();
        }
        return chain;
    }

    public long privateKey() {
        if (refCnt() <= 0) {
            throw new IllegalReferenceCountException();
        }
        return privateKey;
    }

    @Override
    protected void deallocate() {
        SSL.freeX509Chain(chain);
        chain = 0;
        SSL.freePrivateKey(privateKey);
        privateKey = 0;
    }

    @Override
    public OpenSslKeyMaterial retain() {
        super.retain();
        return this;
    }

    @Override
    public OpenSslKeyMaterial retain(int increment) {
        super.retain(increment);
        return this;
    }

    @Override
    public OpenSslKeyMaterial touch() {
        super.touch();
        return this;
    }

    @Override
    public OpenSslKeyMaterial touch(Object hint) {
        return this;
    }
}

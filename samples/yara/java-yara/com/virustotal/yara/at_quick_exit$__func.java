// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
public interface at_quick_exit$__func {

    void apply();
    static MemorySegment allocate(at_quick_exit$__func fi, MemorySession session) {
        return RuntimeHelper.upcallStub(at_quick_exit$__func.class, fi, constants$26.at_quick_exit$__func$FUNC, session);
    }
    static at_quick_exit$__func ofAddress(MemoryAddress addr, MemorySession session) {
        MemorySegment symbol = MemorySegment.ofAddress(addr, 0, session);
        return () -> {
            try {
                constants$27.at_quick_exit$__func$MH.invokeExact((Addressable)symbol);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}



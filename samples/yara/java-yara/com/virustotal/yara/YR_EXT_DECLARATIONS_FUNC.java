// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
public interface YR_EXT_DECLARATIONS_FUNC {

    int apply(java.lang.foreign.MemoryAddress module_object);
    static MemorySegment allocate(YR_EXT_DECLARATIONS_FUNC fi, MemorySession session) {
        return RuntimeHelper.upcallStub(YR_EXT_DECLARATIONS_FUNC.class, fi, constants$165.YR_EXT_DECLARATIONS_FUNC$FUNC, session);
    }
    static YR_EXT_DECLARATIONS_FUNC ofAddress(MemoryAddress addr, MemorySession session) {
        MemorySegment symbol = MemorySegment.ofAddress(addr, 0, session);
        return (java.lang.foreign.MemoryAddress _module_object) -> {
            try {
                return (int)constants$165.YR_EXT_DECLARATIONS_FUNC$MH.invokeExact((Addressable)symbol, (java.lang.foreign.Addressable)_module_object);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}



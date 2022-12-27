// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
public interface YR_COMPILER_CALLBACK_FUNC {

    void apply(int error_level, java.lang.foreign.MemoryAddress file_name, int line_number, java.lang.foreign.MemoryAddress rule, java.lang.foreign.MemoryAddress message, java.lang.foreign.MemoryAddress user_data);
    static MemorySegment allocate(YR_COMPILER_CALLBACK_FUNC fi, MemorySession session) {
        return RuntimeHelper.upcallStub(YR_COMPILER_CALLBACK_FUNC.class, fi, constants$98.YR_COMPILER_CALLBACK_FUNC$FUNC, session);
    }
    static YR_COMPILER_CALLBACK_FUNC ofAddress(MemoryAddress addr, MemorySession session) {
        MemorySegment symbol = MemorySegment.ofAddress(addr, 0, session);
        return (int _error_level, java.lang.foreign.MemoryAddress _file_name, int _line_number, java.lang.foreign.MemoryAddress _rule, java.lang.foreign.MemoryAddress _message, java.lang.foreign.MemoryAddress _user_data) -> {
            try {
                constants$98.YR_COMPILER_CALLBACK_FUNC$MH.invokeExact((Addressable)symbol, _error_level, (java.lang.foreign.Addressable)_file_name, _line_number, (java.lang.foreign.Addressable)_rule, (java.lang.foreign.Addressable)_message, (java.lang.foreign.Addressable)_user_data);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}



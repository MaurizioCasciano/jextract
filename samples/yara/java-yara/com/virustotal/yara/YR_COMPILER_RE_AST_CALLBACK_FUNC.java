// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
public interface YR_COMPILER_RE_AST_CALLBACK_FUNC {

    void apply(java.lang.foreign.MemoryAddress rule, java.lang.foreign.MemoryAddress string_identifier, java.lang.foreign.MemoryAddress re_ast, java.lang.foreign.MemoryAddress user_data);
    static MemorySegment allocate(YR_COMPILER_RE_AST_CALLBACK_FUNC fi, MemorySession session) {
        return RuntimeHelper.upcallStub(YR_COMPILER_RE_AST_CALLBACK_FUNC.class, fi, constants$99.YR_COMPILER_RE_AST_CALLBACK_FUNC$FUNC, session);
    }
    static YR_COMPILER_RE_AST_CALLBACK_FUNC ofAddress(MemoryAddress addr, MemorySession session) {
        MemorySegment symbol = MemorySegment.ofAddress(addr, 0, session);
        return (java.lang.foreign.MemoryAddress _rule, java.lang.foreign.MemoryAddress _string_identifier, java.lang.foreign.MemoryAddress _re_ast, java.lang.foreign.MemoryAddress _user_data) -> {
            try {
                constants$99.YR_COMPILER_RE_AST_CALLBACK_FUNC$MH.invokeExact((Addressable)symbol, (java.lang.foreign.Addressable)_rule, (java.lang.foreign.Addressable)_string_identifier, (java.lang.foreign.Addressable)_re_ast, (java.lang.foreign.Addressable)_user_data);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


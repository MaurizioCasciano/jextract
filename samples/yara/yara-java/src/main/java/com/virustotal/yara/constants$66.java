// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
class constants$66 {

    static final FunctionDescriptor getitimer$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle getitimer$MH = RuntimeHelper.downcallHandle(
        "getitimer",
        constants$66.getitimer$FUNC
    );
    static final FunctionDescriptor setitimer$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle setitimer$MH = RuntimeHelper.downcallHandle(
        "setitimer",
        constants$66.setitimer$FUNC
    );
    static final FunctionDescriptor utimes$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle utimes$MH = RuntimeHelper.downcallHandle(
        "utimes",
        constants$66.utimes$FUNC
    );
    static final FunctionDescriptor lutimes$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle lutimes$MH = RuntimeHelper.downcallHandle(
        "lutimes",
        constants$66.lutimes$FUNC
    );
    static final FunctionDescriptor futimes$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle futimes$MH = RuntimeHelper.downcallHandle(
        "futimes",
        constants$66.futimes$FUNC
    );
    static final FunctionDescriptor yr_stopwatch_start$FUNC = FunctionDescriptor.ofVoid(
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle yr_stopwatch_start$MH = RuntimeHelper.downcallHandle(
        "yr_stopwatch_start",
        constants$66.yr_stopwatch_start$FUNC
    );
}


// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
class constants$20 {

    static final FunctionDescriptor srandom$FUNC = FunctionDescriptor.ofVoid(
        Constants$root.C_INT$LAYOUT
    );
    static final MethodHandle srandom$MH = RuntimeHelper.downcallHandle(
        "srandom",
        constants$20.srandom$FUNC
    );
    static final FunctionDescriptor initstate$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT
    );
    static final MethodHandle initstate$MH = RuntimeHelper.downcallHandle(
        "initstate",
        constants$20.initstate$FUNC
    );
    static final FunctionDescriptor setstate$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle setstate$MH = RuntimeHelper.downcallHandle(
        "setstate",
        constants$20.setstate$FUNC
    );
    static final FunctionDescriptor random_r$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle random_r$MH = RuntimeHelper.downcallHandle(
        "random_r",
        constants$20.random_r$FUNC
    );
    static final FunctionDescriptor srandom_r$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle srandom_r$MH = RuntimeHelper.downcallHandle(
        "srandom_r",
        constants$20.srandom_r$FUNC
    );
    static final FunctionDescriptor initstate_r$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle initstate_r$MH = RuntimeHelper.downcallHandle(
        "initstate_r",
        constants$20.initstate_r$FUNC
    );
}



// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
class constants$22 {

    static final FunctionDescriptor lrand48$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT);
    static final MethodHandle lrand48$MH = RuntimeHelper.downcallHandle(
        "lrand48",
        constants$22.lrand48$FUNC
    );
    static final FunctionDescriptor nrand48$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle nrand48$MH = RuntimeHelper.downcallHandle(
        "nrand48",
        constants$22.nrand48$FUNC
    );
    static final FunctionDescriptor mrand48$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT);
    static final MethodHandle mrand48$MH = RuntimeHelper.downcallHandle(
        "mrand48",
        constants$22.mrand48$FUNC
    );
    static final FunctionDescriptor jrand48$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle jrand48$MH = RuntimeHelper.downcallHandle(
        "jrand48",
        constants$22.jrand48$FUNC
    );
    static final FunctionDescriptor srand48$FUNC = FunctionDescriptor.ofVoid(
        Constants$root.C_LONG_LONG$LAYOUT
    );
    static final MethodHandle srand48$MH = RuntimeHelper.downcallHandle(
        "srand48",
        constants$22.srand48$FUNC
    );
    static final FunctionDescriptor seed48$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle seed48$MH = RuntimeHelper.downcallHandle(
        "seed48",
        constants$22.seed48$FUNC
    );
}



// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
class constants$38 {

    static final FunctionDescriptor strstr$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle strstr$MH = RuntimeHelper.downcallHandle(
        "strstr",
        constants$38.strstr$FUNC
    );
    static final FunctionDescriptor strtok$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle strtok$MH = RuntimeHelper.downcallHandle(
        "strtok",
        constants$38.strtok$FUNC
    );
    static final FunctionDescriptor __strtok_r$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle __strtok_r$MH = RuntimeHelper.downcallHandle(
        "__strtok_r",
        constants$38.__strtok_r$FUNC
    );
    static final FunctionDescriptor strtok_r$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle strtok_r$MH = RuntimeHelper.downcallHandle(
        "strtok_r",
        constants$38.strtok_r$FUNC
    );
    static final FunctionDescriptor strlen$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle strlen$MH = RuntimeHelper.downcallHandle(
        "strlen",
        constants$38.strlen$FUNC
    );
    static final FunctionDescriptor strnlen$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT
    );
    static final MethodHandle strnlen$MH = RuntimeHelper.downcallHandle(
        "strnlen",
        constants$38.strnlen$FUNC
    );
}



// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
class constants$36 {

    static final FunctionDescriptor strncmp$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT
    );
    static final MethodHandle strncmp$MH = RuntimeHelper.downcallHandle(
        "strncmp",
        constants$36.strncmp$FUNC
    );
    static final FunctionDescriptor strcoll$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle strcoll$MH = RuntimeHelper.downcallHandle(
        "strcoll",
        constants$36.strcoll$FUNC
    );
    static final FunctionDescriptor strxfrm$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT
    );
    static final MethodHandle strxfrm$MH = RuntimeHelper.downcallHandle(
        "strxfrm",
        constants$36.strxfrm$FUNC
    );
    static final FunctionDescriptor strcoll_l$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle strcoll_l$MH = RuntimeHelper.downcallHandle(
        "strcoll_l",
        constants$36.strcoll_l$FUNC
    );
    static final FunctionDescriptor strxfrm_l$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle strxfrm_l$MH = RuntimeHelper.downcallHandle(
        "strxfrm_l",
        constants$36.strxfrm_l$FUNC
    );
    static final FunctionDescriptor strdup$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle strdup$MH = RuntimeHelper.downcallHandle(
        "strdup",
        constants$36.strdup$FUNC
    );
}


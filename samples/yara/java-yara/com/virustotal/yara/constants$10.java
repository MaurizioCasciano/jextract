// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
class constants$10 {

    static final FunctionDescriptor getdelim$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle getdelim$MH = RuntimeHelper.downcallHandle(
        "getdelim",
        constants$10.getdelim$FUNC
    );
    static final FunctionDescriptor getline$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle getline$MH = RuntimeHelper.downcallHandle(
        "getline",
        constants$10.getline$FUNC
    );
    static final FunctionDescriptor fputs$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle fputs$MH = RuntimeHelper.downcallHandle(
        "fputs",
        constants$10.fputs$FUNC
    );
    static final FunctionDescriptor puts$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle puts$MH = RuntimeHelper.downcallHandle(
        "puts",
        constants$10.puts$FUNC
    );
    static final FunctionDescriptor ungetc$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle ungetc$MH = RuntimeHelper.downcallHandle(
        "ungetc",
        constants$10.ungetc$FUNC
    );
    static final FunctionDescriptor fread$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle fread$MH = RuntimeHelper.downcallHandle(
        "fread",
        constants$10.fread$FUNC
    );
}



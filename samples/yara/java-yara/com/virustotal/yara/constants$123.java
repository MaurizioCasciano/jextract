// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
class constants$123 {

    static final FunctionDescriptor __gamma$FUNC = FunctionDescriptor.of(Constants$root.C_DOUBLE$LAYOUT,
        Constants$root.C_DOUBLE$LAYOUT
    );
    static final MethodHandle __gamma$MH = RuntimeHelper.downcallHandle(
        "__gamma",
        constants$123.__gamma$FUNC
    );
    static final FunctionDescriptor lgamma_r$FUNC = FunctionDescriptor.of(Constants$root.C_DOUBLE$LAYOUT,
        Constants$root.C_DOUBLE$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle lgamma_r$MH = RuntimeHelper.downcallHandle(
        "lgamma_r",
        constants$123.lgamma_r$FUNC
    );
    static final FunctionDescriptor __lgamma_r$FUNC = FunctionDescriptor.of(Constants$root.C_DOUBLE$LAYOUT,
        Constants$root.C_DOUBLE$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle __lgamma_r$MH = RuntimeHelper.downcallHandle(
        "__lgamma_r",
        constants$123.__lgamma_r$FUNC
    );
    static final FunctionDescriptor rint$FUNC = FunctionDescriptor.of(Constants$root.C_DOUBLE$LAYOUT,
        Constants$root.C_DOUBLE$LAYOUT
    );
    static final MethodHandle rint$MH = RuntimeHelper.downcallHandle(
        "rint",
        constants$123.rint$FUNC
    );
    static final FunctionDescriptor __rint$FUNC = FunctionDescriptor.of(Constants$root.C_DOUBLE$LAYOUT,
        Constants$root.C_DOUBLE$LAYOUT
    );
    static final MethodHandle __rint$MH = RuntimeHelper.downcallHandle(
        "__rint",
        constants$123.__rint$FUNC
    );
    static final FunctionDescriptor nextafter$FUNC = FunctionDescriptor.of(Constants$root.C_DOUBLE$LAYOUT,
        Constants$root.C_DOUBLE$LAYOUT,
        Constants$root.C_DOUBLE$LAYOUT
    );
    static final MethodHandle nextafter$MH = RuntimeHelper.downcallHandle(
        "nextafter",
        constants$123.nextafter$FUNC
    );
}



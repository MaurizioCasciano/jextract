// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
class constants$105 {

    static final FunctionDescriptor yr_free$FUNC = FunctionDescriptor.ofVoid(
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle yr_free$MH = RuntimeHelper.downcallHandle(
        "yr_free",
        constants$105.yr_free$FUNC
    );
    static final FunctionDescriptor yr_strdup$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle yr_strdup$MH = RuntimeHelper.downcallHandle(
        "yr_strdup",
        constants$105.yr_strdup$FUNC
    );
    static final FunctionDescriptor yr_strndup$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT
    );
    static final MethodHandle yr_strndup$MH = RuntimeHelper.downcallHandle(
        "yr_strndup",
        constants$105.yr_strndup$FUNC
    );
    static final FunctionDescriptor yr_heap_alloc$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT);
    static final MethodHandle yr_heap_alloc$MH = RuntimeHelper.downcallHandle(
        "yr_heap_alloc",
        constants$105.yr_heap_alloc$FUNC
    );
    static final FunctionDescriptor yr_heap_free$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT);
    static final MethodHandle yr_heap_free$MH = RuntimeHelper.downcallHandle(
        "yr_heap_free",
        constants$105.yr_heap_free$FUNC
    );
    static final FunctionDescriptor __fpclassify$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_DOUBLE$LAYOUT
    );
    static final MethodHandle __fpclassify$MH = RuntimeHelper.downcallHandle(
        "__fpclassify",
        constants$105.__fpclassify$FUNC
    );
}



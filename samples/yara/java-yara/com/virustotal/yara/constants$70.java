// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
class constants$70 {

    static final FunctionDescriptor pthread_self$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT);
    static final MethodHandle pthread_self$MH = RuntimeHelper.downcallHandle(
        "pthread_self",
        constants$70.pthread_self$FUNC
    );
    static final FunctionDescriptor pthread_equal$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT
    );
    static final MethodHandle pthread_equal$MH = RuntimeHelper.downcallHandle(
        "pthread_equal",
        constants$70.pthread_equal$FUNC
    );
    static final FunctionDescriptor pthread_attr_init$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle pthread_attr_init$MH = RuntimeHelper.downcallHandle(
        "pthread_attr_init",
        constants$70.pthread_attr_init$FUNC
    );
    static final FunctionDescriptor pthread_attr_destroy$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle pthread_attr_destroy$MH = RuntimeHelper.downcallHandle(
        "pthread_attr_destroy",
        constants$70.pthread_attr_destroy$FUNC
    );
    static final FunctionDescriptor pthread_attr_getdetachstate$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle pthread_attr_getdetachstate$MH = RuntimeHelper.downcallHandle(
        "pthread_attr_getdetachstate",
        constants$70.pthread_attr_getdetachstate$FUNC
    );
    static final FunctionDescriptor pthread_attr_setdetachstate$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_INT$LAYOUT
    );
    static final MethodHandle pthread_attr_setdetachstate$MH = RuntimeHelper.downcallHandle(
        "pthread_attr_setdetachstate",
        constants$70.pthread_attr_setdetachstate$FUNC
    );
}



// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
class constants$69 {

    static final FunctionDescriptor pthread_create$__start_routine$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle pthread_create$__start_routine$MH = RuntimeHelper.downcallHandle(
        constants$69.pthread_create$__start_routine$FUNC
    );
    static final FunctionDescriptor pthread_create$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle pthread_create$MH = RuntimeHelper.downcallHandle(
        "pthread_create",
        constants$69.pthread_create$FUNC
    );
    static final FunctionDescriptor pthread_exit$FUNC = FunctionDescriptor.ofVoid(
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle pthread_exit$MH = RuntimeHelper.downcallHandle(
        "pthread_exit",
        constants$69.pthread_exit$FUNC
    );
    static final FunctionDescriptor pthread_join$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle pthread_join$MH = RuntimeHelper.downcallHandle(
        "pthread_join",
        constants$69.pthread_join$FUNC
    );
    static final FunctionDescriptor pthread_detach$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT
    );
    static final MethodHandle pthread_detach$MH = RuntimeHelper.downcallHandle(
        "pthread_detach",
        constants$69.pthread_detach$FUNC
    );
}



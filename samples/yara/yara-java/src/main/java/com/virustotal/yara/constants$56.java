// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
class constants$56 {

    static final FunctionDescriptor ss_iendswith$FUNC = FunctionDescriptor.of(Constants$root.C_BOOL$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle ss_iendswith$MH = RuntimeHelper.downcallHandle(
        "ss_iendswith",
        constants$56.ss_iendswith$FUNC
    );
    static final FunctionDescriptor ss_dup$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle ss_dup$MH = RuntimeHelper.downcallHandle(
        "ss_dup",
        constants$56.ss_dup$FUNC
    );
    static final FunctionDescriptor ss_new$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle ss_new$MH = RuntimeHelper.downcallHandle(
        "ss_new",
        constants$56.ss_new$FUNC
    );
    static final FunctionDescriptor ss_convert_to_wide$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle ss_convert_to_wide$MH = RuntimeHelper.downcallHandle(
        "ss_convert_to_wide",
        constants$56.ss_convert_to_wide$FUNC
    );
    static final FunctionDescriptor yr_bitmask_find_non_colliding_offset$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle yr_bitmask_find_non_colliding_offset$MH = RuntimeHelper.downcallHandle(
        "yr_bitmask_find_non_colliding_offset",
        constants$56.yr_bitmask_find_non_colliding_offset$FUNC
    );
    static final FunctionDescriptor YR_HASH_TABLE_FREE_VALUE_FUNC$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
}


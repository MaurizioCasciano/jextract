// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
class constants$62 {

    static final  OfInt __daylight$LAYOUT = Constants$root.C_INT$LAYOUT;
    static final VarHandle __daylight$VH = constants$62.__daylight$LAYOUT.varHandle();
    static final MemorySegment __daylight$SEGMENT = RuntimeHelper.lookupGlobalVariable("__daylight", constants$62.__daylight$LAYOUT);
    static final  OfLong __timezone$LAYOUT = Constants$root.C_LONG_LONG$LAYOUT;
    static final VarHandle __timezone$VH = constants$62.__timezone$LAYOUT.varHandle();
    static final MemorySegment __timezone$SEGMENT = RuntimeHelper.lookupGlobalVariable("__timezone", constants$62.__timezone$LAYOUT);
    static final  SequenceLayout tzname$LAYOUT = MemoryLayout.sequenceLayout(2, Constants$root.C_POINTER$LAYOUT);
    static final MemorySegment tzname$SEGMENT = RuntimeHelper.lookupGlobalVariable("tzname", constants$62.tzname$LAYOUT);
    static final FunctionDescriptor tzset$FUNC = FunctionDescriptor.ofVoid();
    static final MethodHandle tzset$MH = RuntimeHelper.downcallHandle(
        "tzset",
        constants$62.tzset$FUNC
    );
    static final  OfInt daylight$LAYOUT = Constants$root.C_INT$LAYOUT;
    static final VarHandle daylight$VH = constants$62.daylight$LAYOUT.varHandle();
    static final MemorySegment daylight$SEGMENT = RuntimeHelper.lookupGlobalVariable("daylight", constants$62.daylight$LAYOUT);
    static final  OfLong timezone$LAYOUT = Constants$root.C_LONG_LONG$LAYOUT;
    static final VarHandle timezone$VH = constants$62.timezone$LAYOUT.varHandle();
    static final MemorySegment timezone$SEGMENT = RuntimeHelper.lookupGlobalVariable("timezone", constants$62.timezone$LAYOUT);
}



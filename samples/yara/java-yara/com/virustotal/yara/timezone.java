// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
public class timezone {

    static final  GroupLayout $struct$LAYOUT = MemoryLayout.structLayout(
        Constants$root.C_INT$LAYOUT.withName("tz_minuteswest"),
        Constants$root.C_INT$LAYOUT.withName("tz_dsttime")
    ).withName("timezone");
    public static MemoryLayout $LAYOUT() {
        return timezone.$struct$LAYOUT;
    }
    static final VarHandle tz_minuteswest$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("tz_minuteswest"));
    public static VarHandle tz_minuteswest$VH() {
        return timezone.tz_minuteswest$VH;
    }
    public static int tz_minuteswest$get(MemorySegment seg) {
        return (int)timezone.tz_minuteswest$VH.get(seg);
    }
    public static void tz_minuteswest$set( MemorySegment seg, int x) {
        timezone.tz_minuteswest$VH.set(seg, x);
    }
    public static int tz_minuteswest$get(MemorySegment seg, long index) {
        return (int)timezone.tz_minuteswest$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void tz_minuteswest$set(MemorySegment seg, long index, int x) {
        timezone.tz_minuteswest$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle tz_dsttime$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("tz_dsttime"));
    public static VarHandle tz_dsttime$VH() {
        return timezone.tz_dsttime$VH;
    }
    public static int tz_dsttime$get(MemorySegment seg) {
        return (int)timezone.tz_dsttime$VH.get(seg);
    }
    public static void tz_dsttime$set( MemorySegment seg, int x) {
        timezone.tz_dsttime$VH.set(seg, x);
    }
    public static int tz_dsttime$get(MemorySegment seg, long index) {
        return (int)timezone.tz_dsttime$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void tz_dsttime$set(MemorySegment seg, long index, int x) {
        timezone.tz_dsttime$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, MemorySession session) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, session); }
}



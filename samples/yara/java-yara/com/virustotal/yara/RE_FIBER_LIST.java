// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
public class RE_FIBER_LIST {

    static final  GroupLayout $struct$LAYOUT = MemoryLayout.structLayout(
        Constants$root.C_POINTER$LAYOUT.withName("head"),
        Constants$root.C_POINTER$LAYOUT.withName("tail")
    ).withName("RE_FIBER_LIST");
    public static MemoryLayout $LAYOUT() {
        return RE_FIBER_LIST.$struct$LAYOUT;
    }
    static final VarHandle head$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("head"));
    public static VarHandle head$VH() {
        return RE_FIBER_LIST.head$VH;
    }
    public static MemoryAddress head$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)RE_FIBER_LIST.head$VH.get(seg);
    }
    public static void head$set( MemorySegment seg, MemoryAddress x) {
        RE_FIBER_LIST.head$VH.set(seg, x);
    }
    public static MemoryAddress head$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)RE_FIBER_LIST.head$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void head$set(MemorySegment seg, long index, MemoryAddress x) {
        RE_FIBER_LIST.head$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle tail$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("tail"));
    public static VarHandle tail$VH() {
        return RE_FIBER_LIST.tail$VH;
    }
    public static MemoryAddress tail$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)RE_FIBER_LIST.tail$VH.get(seg);
    }
    public static void tail$set( MemorySegment seg, MemoryAddress x) {
        RE_FIBER_LIST.tail$VH.set(seg, x);
    }
    public static MemoryAddress tail$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)RE_FIBER_LIST.tail$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void tail$set(MemorySegment seg, long index, MemoryAddress x) {
        RE_FIBER_LIST.tail$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, MemorySession session) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, session); }
}



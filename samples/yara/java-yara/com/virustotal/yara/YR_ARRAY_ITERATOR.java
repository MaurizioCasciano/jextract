// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
public class YR_ARRAY_ITERATOR {

    static final  GroupLayout $struct$LAYOUT = MemoryLayout.structLayout(
        Constants$root.C_POINTER$LAYOUT.withName("array"),
        Constants$root.C_INT$LAYOUT.withName("index"),
        MemoryLayout.paddingLayout(32)
    ).withName("YR_ARRAY_ITERATOR");
    public static MemoryLayout $LAYOUT() {
        return YR_ARRAY_ITERATOR.$struct$LAYOUT;
    }
    static final VarHandle array$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("array"));
    public static VarHandle array$VH() {
        return YR_ARRAY_ITERATOR.array$VH;
    }
    public static MemoryAddress array$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)YR_ARRAY_ITERATOR.array$VH.get(seg);
    }
    public static void array$set( MemorySegment seg, MemoryAddress x) {
        YR_ARRAY_ITERATOR.array$VH.set(seg, x);
    }
    public static MemoryAddress array$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)YR_ARRAY_ITERATOR.array$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void array$set(MemorySegment seg, long index, MemoryAddress x) {
        YR_ARRAY_ITERATOR.array$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle index$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("index"));
    public static VarHandle index$VH() {
        return YR_ARRAY_ITERATOR.index$VH;
    }
    public static int index$get(MemorySegment seg) {
        return (int)YR_ARRAY_ITERATOR.index$VH.get(seg);
    }
    public static void index$set( MemorySegment seg, int x) {
        YR_ARRAY_ITERATOR.index$VH.set(seg, x);
    }
    public static int index$get(MemorySegment seg, long index) {
        return (int)YR_ARRAY_ITERATOR.index$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void index$set(MemorySegment seg, long index, int x) {
        YR_ARRAY_ITERATOR.index$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, MemorySession session) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, session); }
}


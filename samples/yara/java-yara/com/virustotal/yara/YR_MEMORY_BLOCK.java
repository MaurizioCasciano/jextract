// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
public class YR_MEMORY_BLOCK {

    static final  GroupLayout $struct$LAYOUT = MemoryLayout.structLayout(
        Constants$root.C_LONG_LONG$LAYOUT.withName("size"),
        Constants$root.C_LONG_LONG$LAYOUT.withName("base"),
        Constants$root.C_POINTER$LAYOUT.withName("context"),
        Constants$root.C_POINTER$LAYOUT.withName("fetch_data")
    ).withName("YR_MEMORY_BLOCK");
    public static MemoryLayout $LAYOUT() {
        return YR_MEMORY_BLOCK.$struct$LAYOUT;
    }
    static final VarHandle size$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("size"));
    public static VarHandle size$VH() {
        return YR_MEMORY_BLOCK.size$VH;
    }
    public static long size$get(MemorySegment seg) {
        return (long)YR_MEMORY_BLOCK.size$VH.get(seg);
    }
    public static void size$set( MemorySegment seg, long x) {
        YR_MEMORY_BLOCK.size$VH.set(seg, x);
    }
    public static long size$get(MemorySegment seg, long index) {
        return (long)YR_MEMORY_BLOCK.size$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void size$set(MemorySegment seg, long index, long x) {
        YR_MEMORY_BLOCK.size$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle base$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("base"));
    public static VarHandle base$VH() {
        return YR_MEMORY_BLOCK.base$VH;
    }
    public static long base$get(MemorySegment seg) {
        return (long)YR_MEMORY_BLOCK.base$VH.get(seg);
    }
    public static void base$set( MemorySegment seg, long x) {
        YR_MEMORY_BLOCK.base$VH.set(seg, x);
    }
    public static long base$get(MemorySegment seg, long index) {
        return (long)YR_MEMORY_BLOCK.base$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void base$set(MemorySegment seg, long index, long x) {
        YR_MEMORY_BLOCK.base$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle context$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("context"));
    public static VarHandle context$VH() {
        return YR_MEMORY_BLOCK.context$VH;
    }
    public static MemoryAddress context$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)YR_MEMORY_BLOCK.context$VH.get(seg);
    }
    public static void context$set( MemorySegment seg, MemoryAddress x) {
        YR_MEMORY_BLOCK.context$VH.set(seg, x);
    }
    public static MemoryAddress context$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)YR_MEMORY_BLOCK.context$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void context$set(MemorySegment seg, long index, MemoryAddress x) {
        YR_MEMORY_BLOCK.context$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle fetch_data$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("fetch_data"));
    public static VarHandle fetch_data$VH() {
        return YR_MEMORY_BLOCK.fetch_data$VH;
    }
    public static MemoryAddress fetch_data$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)YR_MEMORY_BLOCK.fetch_data$VH.get(seg);
    }
    public static void fetch_data$set( MemorySegment seg, MemoryAddress x) {
        YR_MEMORY_BLOCK.fetch_data$VH.set(seg, x);
    }
    public static MemoryAddress fetch_data$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)YR_MEMORY_BLOCK.fetch_data$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void fetch_data$set(MemorySegment seg, long index, MemoryAddress x) {
        YR_MEMORY_BLOCK.fetch_data$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static YR_MEMORY_BLOCK_FETCH_DATA_FUNC fetch_data (MemorySegment segment, MemorySession session) {
        return YR_MEMORY_BLOCK_FETCH_DATA_FUNC.ofAddress(fetch_data$get(segment), session);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, MemorySession session) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, session); }
}



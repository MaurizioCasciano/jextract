// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
public class YR_MATCH {

    static final  GroupLayout $struct$LAYOUT = MemoryLayout.structLayout(
        Constants$root.C_LONG_LONG$LAYOUT.withName("base"),
        Constants$root.C_LONG_LONG$LAYOUT.withName("offset"),
        Constants$root.C_INT$LAYOUT.withName("match_length"),
        Constants$root.C_INT$LAYOUT.withName("data_length"),
        Constants$root.C_POINTER$LAYOUT.withName("data"),
        Constants$root.C_POINTER$LAYOUT.withName("prev"),
        Constants$root.C_POINTER$LAYOUT.withName("next"),
        Constants$root.C_INT$LAYOUT.withName("chain_length"),
        Constants$root.C_BOOL$LAYOUT.withName("is_private"),
        MemoryLayout.paddingLayout(24)
    ).withName("YR_MATCH");
    public static MemoryLayout $LAYOUT() {
        return YR_MATCH.$struct$LAYOUT;
    }
    static final VarHandle base$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("base"));
    public static VarHandle base$VH() {
        return YR_MATCH.base$VH;
    }
    public static long base$get(MemorySegment seg) {
        return (long)YR_MATCH.base$VH.get(seg);
    }
    public static void base$set( MemorySegment seg, long x) {
        YR_MATCH.base$VH.set(seg, x);
    }
    public static long base$get(MemorySegment seg, long index) {
        return (long)YR_MATCH.base$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void base$set(MemorySegment seg, long index, long x) {
        YR_MATCH.base$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle offset$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("offset"));
    public static VarHandle offset$VH() {
        return YR_MATCH.offset$VH;
    }
    public static long offset$get(MemorySegment seg) {
        return (long)YR_MATCH.offset$VH.get(seg);
    }
    public static void offset$set( MemorySegment seg, long x) {
        YR_MATCH.offset$VH.set(seg, x);
    }
    public static long offset$get(MemorySegment seg, long index) {
        return (long)YR_MATCH.offset$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void offset$set(MemorySegment seg, long index, long x) {
        YR_MATCH.offset$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle match_length$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("match_length"));
    public static VarHandle match_length$VH() {
        return YR_MATCH.match_length$VH;
    }
    public static int match_length$get(MemorySegment seg) {
        return (int)YR_MATCH.match_length$VH.get(seg);
    }
    public static void match_length$set( MemorySegment seg, int x) {
        YR_MATCH.match_length$VH.set(seg, x);
    }
    public static int match_length$get(MemorySegment seg, long index) {
        return (int)YR_MATCH.match_length$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void match_length$set(MemorySegment seg, long index, int x) {
        YR_MATCH.match_length$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle data_length$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("data_length"));
    public static VarHandle data_length$VH() {
        return YR_MATCH.data_length$VH;
    }
    public static int data_length$get(MemorySegment seg) {
        return (int)YR_MATCH.data_length$VH.get(seg);
    }
    public static void data_length$set( MemorySegment seg, int x) {
        YR_MATCH.data_length$VH.set(seg, x);
    }
    public static int data_length$get(MemorySegment seg, long index) {
        return (int)YR_MATCH.data_length$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void data_length$set(MemorySegment seg, long index, int x) {
        YR_MATCH.data_length$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle data$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("data"));
    public static VarHandle data$VH() {
        return YR_MATCH.data$VH;
    }
    public static MemoryAddress data$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)YR_MATCH.data$VH.get(seg);
    }
    public static void data$set( MemorySegment seg, MemoryAddress x) {
        YR_MATCH.data$VH.set(seg, x);
    }
    public static MemoryAddress data$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)YR_MATCH.data$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void data$set(MemorySegment seg, long index, MemoryAddress x) {
        YR_MATCH.data$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle prev$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("prev"));
    public static VarHandle prev$VH() {
        return YR_MATCH.prev$VH;
    }
    public static MemoryAddress prev$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)YR_MATCH.prev$VH.get(seg);
    }
    public static void prev$set( MemorySegment seg, MemoryAddress x) {
        YR_MATCH.prev$VH.set(seg, x);
    }
    public static MemoryAddress prev$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)YR_MATCH.prev$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void prev$set(MemorySegment seg, long index, MemoryAddress x) {
        YR_MATCH.prev$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle next$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("next"));
    public static VarHandle next$VH() {
        return YR_MATCH.next$VH;
    }
    public static MemoryAddress next$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)YR_MATCH.next$VH.get(seg);
    }
    public static void next$set( MemorySegment seg, MemoryAddress x) {
        YR_MATCH.next$VH.set(seg, x);
    }
    public static MemoryAddress next$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)YR_MATCH.next$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void next$set(MemorySegment seg, long index, MemoryAddress x) {
        YR_MATCH.next$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle chain_length$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("chain_length"));
    public static VarHandle chain_length$VH() {
        return YR_MATCH.chain_length$VH;
    }
    public static int chain_length$get(MemorySegment seg) {
        return (int)YR_MATCH.chain_length$VH.get(seg);
    }
    public static void chain_length$set( MemorySegment seg, int x) {
        YR_MATCH.chain_length$VH.set(seg, x);
    }
    public static int chain_length$get(MemorySegment seg, long index) {
        return (int)YR_MATCH.chain_length$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void chain_length$set(MemorySegment seg, long index, int x) {
        YR_MATCH.chain_length$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle is_private$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("is_private"));
    public static VarHandle is_private$VH() {
        return YR_MATCH.is_private$VH;
    }
    public static boolean is_private$get(MemorySegment seg) {
        return (boolean)YR_MATCH.is_private$VH.get(seg);
    }
    public static void is_private$set( MemorySegment seg, boolean x) {
        YR_MATCH.is_private$VH.set(seg, x);
    }
    public static boolean is_private$get(MemorySegment seg, long index) {
        return (boolean)YR_MATCH.is_private$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void is_private$set(MemorySegment seg, long index, boolean x) {
        YR_MATCH.is_private$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, MemorySession session) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, session); }
}



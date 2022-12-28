// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
public class YR_AC_AUTOMATON {

    static final  GroupLayout $struct$LAYOUT = MemoryLayout.structLayout(
        Constants$root.C_POINTER$LAYOUT.withName("arena"),
        Constants$root.C_INT$LAYOUT.withName("tables_size"),
        Constants$root.C_INT$LAYOUT.withName("t_table_unused_candidate"),
        Constants$root.C_POINTER$LAYOUT.withName("bitmask"),
        Constants$root.C_POINTER$LAYOUT.withName("root")
    ).withName("YR_AC_AUTOMATON");
    public static MemoryLayout $LAYOUT() {
        return YR_AC_AUTOMATON.$struct$LAYOUT;
    }
    static final VarHandle arena$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("arena"));
    public static VarHandle arena$VH() {
        return YR_AC_AUTOMATON.arena$VH;
    }
    public static MemoryAddress arena$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)YR_AC_AUTOMATON.arena$VH.get(seg);
    }
    public static void arena$set( MemorySegment seg, MemoryAddress x) {
        YR_AC_AUTOMATON.arena$VH.set(seg, x);
    }
    public static MemoryAddress arena$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)YR_AC_AUTOMATON.arena$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void arena$set(MemorySegment seg, long index, MemoryAddress x) {
        YR_AC_AUTOMATON.arena$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle tables_size$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("tables_size"));
    public static VarHandle tables_size$VH() {
        return YR_AC_AUTOMATON.tables_size$VH;
    }
    public static int tables_size$get(MemorySegment seg) {
        return (int)YR_AC_AUTOMATON.tables_size$VH.get(seg);
    }
    public static void tables_size$set( MemorySegment seg, int x) {
        YR_AC_AUTOMATON.tables_size$VH.set(seg, x);
    }
    public static int tables_size$get(MemorySegment seg, long index) {
        return (int)YR_AC_AUTOMATON.tables_size$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void tables_size$set(MemorySegment seg, long index, int x) {
        YR_AC_AUTOMATON.tables_size$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle t_table_unused_candidate$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("t_table_unused_candidate"));
    public static VarHandle t_table_unused_candidate$VH() {
        return YR_AC_AUTOMATON.t_table_unused_candidate$VH;
    }
    public static int t_table_unused_candidate$get(MemorySegment seg) {
        return (int)YR_AC_AUTOMATON.t_table_unused_candidate$VH.get(seg);
    }
    public static void t_table_unused_candidate$set( MemorySegment seg, int x) {
        YR_AC_AUTOMATON.t_table_unused_candidate$VH.set(seg, x);
    }
    public static int t_table_unused_candidate$get(MemorySegment seg, long index) {
        return (int)YR_AC_AUTOMATON.t_table_unused_candidate$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void t_table_unused_candidate$set(MemorySegment seg, long index, int x) {
        YR_AC_AUTOMATON.t_table_unused_candidate$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle bitmask$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("bitmask"));
    public static VarHandle bitmask$VH() {
        return YR_AC_AUTOMATON.bitmask$VH;
    }
    public static MemoryAddress bitmask$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)YR_AC_AUTOMATON.bitmask$VH.get(seg);
    }
    public static void bitmask$set( MemorySegment seg, MemoryAddress x) {
        YR_AC_AUTOMATON.bitmask$VH.set(seg, x);
    }
    public static MemoryAddress bitmask$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)YR_AC_AUTOMATON.bitmask$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void bitmask$set(MemorySegment seg, long index, MemoryAddress x) {
        YR_AC_AUTOMATON.bitmask$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle root$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("root"));
    public static VarHandle root$VH() {
        return YR_AC_AUTOMATON.root$VH;
    }
    public static MemoryAddress root$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)YR_AC_AUTOMATON.root$VH.get(seg);
    }
    public static void root$set( MemorySegment seg, MemoryAddress x) {
        YR_AC_AUTOMATON.root$VH.set(seg, x);
    }
    public static MemoryAddress root$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)YR_AC_AUTOMATON.root$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void root$set(MemorySegment seg, long index, MemoryAddress x) {
        YR_AC_AUTOMATON.root$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, MemorySession session) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, session); }
}


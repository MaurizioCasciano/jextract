// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
public class _YR_HASH_TABLE_ENTRY {

    static final  GroupLayout $struct$LAYOUT = MemoryLayout.structLayout(
        Constants$root.C_POINTER$LAYOUT.withName("key"),
        Constants$root.C_LONG_LONG$LAYOUT.withName("key_length"),
        Constants$root.C_POINTER$LAYOUT.withName("ns"),
        Constants$root.C_POINTER$LAYOUT.withName("value"),
        Constants$root.C_POINTER$LAYOUT.withName("next")
    ).withName("_YR_HASH_TABLE_ENTRY");
    public static MemoryLayout $LAYOUT() {
        return _YR_HASH_TABLE_ENTRY.$struct$LAYOUT;
    }
    static final VarHandle key$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("key"));
    public static VarHandle key$VH() {
        return _YR_HASH_TABLE_ENTRY.key$VH;
    }
    public static MemoryAddress key$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)_YR_HASH_TABLE_ENTRY.key$VH.get(seg);
    }
    public static void key$set( MemorySegment seg, MemoryAddress x) {
        _YR_HASH_TABLE_ENTRY.key$VH.set(seg, x);
    }
    public static MemoryAddress key$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)_YR_HASH_TABLE_ENTRY.key$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void key$set(MemorySegment seg, long index, MemoryAddress x) {
        _YR_HASH_TABLE_ENTRY.key$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle key_length$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("key_length"));
    public static VarHandle key_length$VH() {
        return _YR_HASH_TABLE_ENTRY.key_length$VH;
    }
    public static long key_length$get(MemorySegment seg) {
        return (long)_YR_HASH_TABLE_ENTRY.key_length$VH.get(seg);
    }
    public static void key_length$set( MemorySegment seg, long x) {
        _YR_HASH_TABLE_ENTRY.key_length$VH.set(seg, x);
    }
    public static long key_length$get(MemorySegment seg, long index) {
        return (long)_YR_HASH_TABLE_ENTRY.key_length$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void key_length$set(MemorySegment seg, long index, long x) {
        _YR_HASH_TABLE_ENTRY.key_length$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle ns$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("ns"));
    public static VarHandle ns$VH() {
        return _YR_HASH_TABLE_ENTRY.ns$VH;
    }
    public static MemoryAddress ns$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)_YR_HASH_TABLE_ENTRY.ns$VH.get(seg);
    }
    public static void ns$set( MemorySegment seg, MemoryAddress x) {
        _YR_HASH_TABLE_ENTRY.ns$VH.set(seg, x);
    }
    public static MemoryAddress ns$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)_YR_HASH_TABLE_ENTRY.ns$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void ns$set(MemorySegment seg, long index, MemoryAddress x) {
        _YR_HASH_TABLE_ENTRY.ns$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle value$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("value"));
    public static VarHandle value$VH() {
        return _YR_HASH_TABLE_ENTRY.value$VH;
    }
    public static MemoryAddress value$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)_YR_HASH_TABLE_ENTRY.value$VH.get(seg);
    }
    public static void value$set( MemorySegment seg, MemoryAddress x) {
        _YR_HASH_TABLE_ENTRY.value$VH.set(seg, x);
    }
    public static MemoryAddress value$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)_YR_HASH_TABLE_ENTRY.value$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void value$set(MemorySegment seg, long index, MemoryAddress x) {
        _YR_HASH_TABLE_ENTRY.value$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle next$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("next"));
    public static VarHandle next$VH() {
        return _YR_HASH_TABLE_ENTRY.next$VH;
    }
    public static MemoryAddress next$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)_YR_HASH_TABLE_ENTRY.next$VH.get(seg);
    }
    public static void next$set( MemorySegment seg, MemoryAddress x) {
        _YR_HASH_TABLE_ENTRY.next$VH.set(seg, x);
    }
    public static MemoryAddress next$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)_YR_HASH_TABLE_ENTRY.next$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void next$set(MemorySegment seg, long index, MemoryAddress x) {
        _YR_HASH_TABLE_ENTRY.next$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, MemorySession session) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, session); }
}


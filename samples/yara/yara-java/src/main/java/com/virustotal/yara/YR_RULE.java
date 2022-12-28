// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
public class YR_RULE {

    static final  GroupLayout $struct$LAYOUT = MemoryLayout.structLayout(
        Constants$root.C_INT$LAYOUT.withName("flags"),
        Constants$root.C_INT$LAYOUT.withName("num_atoms"),
        MemoryLayout.unionLayout(
            Constants$root.C_POINTER$LAYOUT.withName("identifier"),
            MemoryLayout.structLayout(
                Constants$root.C_INT$LAYOUT.withName("buffer_id"),
                Constants$root.C_INT$LAYOUT.withName("offset")
            ).withName("identifier_")
        ).withName("$anon$0"),
        MemoryLayout.unionLayout(
            Constants$root.C_POINTER$LAYOUT.withName("tags"),
            MemoryLayout.structLayout(
                Constants$root.C_INT$LAYOUT.withName("buffer_id"),
                Constants$root.C_INT$LAYOUT.withName("offset")
            ).withName("tags_")
        ).withName("$anon$1"),
        MemoryLayout.unionLayout(
            Constants$root.C_POINTER$LAYOUT.withName("metas"),
            MemoryLayout.structLayout(
                Constants$root.C_INT$LAYOUT.withName("buffer_id"),
                Constants$root.C_INT$LAYOUT.withName("offset")
            ).withName("metas_")
        ).withName("$anon$2"),
        MemoryLayout.unionLayout(
            Constants$root.C_POINTER$LAYOUT.withName("strings"),
            MemoryLayout.structLayout(
                Constants$root.C_INT$LAYOUT.withName("buffer_id"),
                Constants$root.C_INT$LAYOUT.withName("offset")
            ).withName("strings_")
        ).withName("$anon$3"),
        MemoryLayout.unionLayout(
            Constants$root.C_POINTER$LAYOUT.withName("ns"),
            MemoryLayout.structLayout(
                Constants$root.C_INT$LAYOUT.withName("buffer_id"),
                Constants$root.C_INT$LAYOUT.withName("offset")
            ).withName("ns_")
        ).withName("$anon$4")
    ).withName("YR_RULE");
    public static MemoryLayout $LAYOUT() {
        return YR_RULE.$struct$LAYOUT;
    }
    static final VarHandle flags$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("flags"));
    public static VarHandle flags$VH() {
        return YR_RULE.flags$VH;
    }
    public static int flags$get(MemorySegment seg) {
        return (int)YR_RULE.flags$VH.get(seg);
    }
    public static void flags$set( MemorySegment seg, int x) {
        YR_RULE.flags$VH.set(seg, x);
    }
    public static int flags$get(MemorySegment seg, long index) {
        return (int)YR_RULE.flags$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void flags$set(MemorySegment seg, long index, int x) {
        YR_RULE.flags$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle num_atoms$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("num_atoms"));
    public static VarHandle num_atoms$VH() {
        return YR_RULE.num_atoms$VH;
    }
    public static int num_atoms$get(MemorySegment seg) {
        return (int)YR_RULE.num_atoms$VH.get(seg);
    }
    public static void num_atoms$set( MemorySegment seg, int x) {
        YR_RULE.num_atoms$VH.set(seg, x);
    }
    public static int num_atoms$get(MemorySegment seg, long index) {
        return (int)YR_RULE.num_atoms$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void num_atoms$set(MemorySegment seg, long index, int x) {
        YR_RULE.num_atoms$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle identifier$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("$anon$0"), MemoryLayout.PathElement.groupElement("identifier"));
    public static VarHandle identifier$VH() {
        return YR_RULE.identifier$VH;
    }
    public static MemoryAddress identifier$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)YR_RULE.identifier$VH.get(seg);
    }
    public static void identifier$set( MemorySegment seg, MemoryAddress x) {
        YR_RULE.identifier$VH.set(seg, x);
    }
    public static MemoryAddress identifier$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)YR_RULE.identifier$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void identifier$set(MemorySegment seg, long index, MemoryAddress x) {
        YR_RULE.identifier$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static MemorySegment identifier_$slice(MemorySegment seg) {
        return seg.asSlice(8, 8);
    }
    static final VarHandle tags$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("$anon$1"), MemoryLayout.PathElement.groupElement("tags"));
    public static VarHandle tags$VH() {
        return YR_RULE.tags$VH;
    }
    public static MemoryAddress tags$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)YR_RULE.tags$VH.get(seg);
    }
    public static void tags$set( MemorySegment seg, MemoryAddress x) {
        YR_RULE.tags$VH.set(seg, x);
    }
    public static MemoryAddress tags$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)YR_RULE.tags$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void tags$set(MemorySegment seg, long index, MemoryAddress x) {
        YR_RULE.tags$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static MemorySegment tags_$slice(MemorySegment seg) {
        return seg.asSlice(16, 8);
    }
    static final VarHandle metas$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("$anon$2"), MemoryLayout.PathElement.groupElement("metas"));
    public static VarHandle metas$VH() {
        return YR_RULE.metas$VH;
    }
    public static MemoryAddress metas$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)YR_RULE.metas$VH.get(seg);
    }
    public static void metas$set( MemorySegment seg, MemoryAddress x) {
        YR_RULE.metas$VH.set(seg, x);
    }
    public static MemoryAddress metas$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)YR_RULE.metas$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void metas$set(MemorySegment seg, long index, MemoryAddress x) {
        YR_RULE.metas$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static MemorySegment metas_$slice(MemorySegment seg) {
        return seg.asSlice(24, 8);
    }
    static final VarHandle strings$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("$anon$3"), MemoryLayout.PathElement.groupElement("strings"));
    public static VarHandle strings$VH() {
        return YR_RULE.strings$VH;
    }
    public static MemoryAddress strings$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)YR_RULE.strings$VH.get(seg);
    }
    public static void strings$set( MemorySegment seg, MemoryAddress x) {
        YR_RULE.strings$VH.set(seg, x);
    }
    public static MemoryAddress strings$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)YR_RULE.strings$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void strings$set(MemorySegment seg, long index, MemoryAddress x) {
        YR_RULE.strings$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static MemorySegment strings_$slice(MemorySegment seg) {
        return seg.asSlice(32, 8);
    }
    static final VarHandle ns$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("$anon$4"), MemoryLayout.PathElement.groupElement("ns"));
    public static VarHandle ns$VH() {
        return YR_RULE.ns$VH;
    }
    public static MemoryAddress ns$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)YR_RULE.ns$VH.get(seg);
    }
    public static void ns$set( MemorySegment seg, MemoryAddress x) {
        YR_RULE.ns$VH.set(seg, x);
    }
    public static MemoryAddress ns$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)YR_RULE.ns$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void ns$set(MemorySegment seg, long index, MemoryAddress x) {
        YR_RULE.ns$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static MemorySegment ns_$slice(MemorySegment seg) {
        return seg.asSlice(40, 8);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, MemorySession session) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, session); }
}


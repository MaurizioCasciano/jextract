// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
public class YR_STRUCTURE_MEMBER {

    static final  GroupLayout $struct$LAYOUT = MemoryLayout.structLayout(
        Constants$root.C_POINTER$LAYOUT.withName("object"),
        Constants$root.C_POINTER$LAYOUT.withName("next")
    ).withName("YR_STRUCTURE_MEMBER");
    public static MemoryLayout $LAYOUT() {
        return YR_STRUCTURE_MEMBER.$struct$LAYOUT;
    }
    static final VarHandle object$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("object"));
    public static VarHandle object$VH() {
        return YR_STRUCTURE_MEMBER.object$VH;
    }
    public static MemoryAddress object$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)YR_STRUCTURE_MEMBER.object$VH.get(seg);
    }
    public static void object$set( MemorySegment seg, MemoryAddress x) {
        YR_STRUCTURE_MEMBER.object$VH.set(seg, x);
    }
    public static MemoryAddress object$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)YR_STRUCTURE_MEMBER.object$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void object$set(MemorySegment seg, long index, MemoryAddress x) {
        YR_STRUCTURE_MEMBER.object$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle next$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("next"));
    public static VarHandle next$VH() {
        return YR_STRUCTURE_MEMBER.next$VH;
    }
    public static MemoryAddress next$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)YR_STRUCTURE_MEMBER.next$VH.get(seg);
    }
    public static void next$set( MemorySegment seg, MemoryAddress x) {
        YR_STRUCTURE_MEMBER.next$VH.set(seg, x);
    }
    public static MemoryAddress next$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)YR_STRUCTURE_MEMBER.next$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void next$set(MemorySegment seg, long index, MemoryAddress x) {
        YR_STRUCTURE_MEMBER.next$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, MemorySession session) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, session); }
}


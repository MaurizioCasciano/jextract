// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
public class _YR_FIXUP {

    static final  GroupLayout $struct$LAYOUT = MemoryLayout.structLayout(
        MemoryLayout.structLayout(
            Constants$root.C_INT$LAYOUT.withName("buffer_id"),
            Constants$root.C_INT$LAYOUT.withName("offset")
        ).withName("ref"),
        Constants$root.C_POINTER$LAYOUT.withName("next")
    ).withName("_YR_FIXUP");
    public static MemoryLayout $LAYOUT() {
        return _YR_FIXUP.$struct$LAYOUT;
    }
    public static MemorySegment ref$slice(MemorySegment seg) {
        return seg.asSlice(0, 8);
    }
    static final VarHandle next$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("next"));
    public static VarHandle next$VH() {
        return _YR_FIXUP.next$VH;
    }
    public static MemoryAddress next$get(MemorySegment seg) {
        return (java.lang.foreign.MemoryAddress)_YR_FIXUP.next$VH.get(seg);
    }
    public static void next$set( MemorySegment seg, MemoryAddress x) {
        _YR_FIXUP.next$VH.set(seg, x);
    }
    public static MemoryAddress next$get(MemorySegment seg, long index) {
        return (java.lang.foreign.MemoryAddress)_YR_FIXUP.next$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void next$set(MemorySegment seg, long index, MemoryAddress x) {
        _YR_FIXUP.next$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, MemorySession session) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, session); }
}


pragma solidity ^0.4.17;

import "./BytesUtils.sol";
import "./Buffer.sol";

/**
 * @dev RRUtils is a library that provides utilities for parsing DNS resource records.
 */
library RRUtils {
    using BytesUtils for *;
    using Buffer for *;
    event Logger(string name);
    event LoggerInt(int name);
    event LoggerBytes(bytes name);

    /**
     * @dev Returns the number of bytes in the DNS name at 'offset' in 'self'.
     * @param self The byte array to read a name from.
     * @param offset The offset to start reading at.
     * @return The length of the DNS name at 'offset', in bytes.
     */
    function nameLength(bytes memory self, uint offset) internal pure returns(uint) {
        uint idx = offset;
        while (true) {
            assert(idx < self.length);
            uint labelLen = self.readUint8(idx);
            idx += labelLen + 1;
            if (labelLen == 0) break;
        }
        return idx - offset;
    }

    /**
     * @dev Returns the number of labels in the DNS name at 'offset' in 'self'.
     * @param self The byte array to read a name from.
     * @param offset The offset to start reading at.
     * @return The number of labels in the DNS name at 'offset', in bytes.
     */
    function labelCount(bytes memory self, uint offset) internal pure returns(uint) {
        uint count = 0;
        while (true) {
            assert(offset < self.length);
            uint labelLen = self.readUint8(offset);
            offset += labelLen + 1;
            if (labelLen == 0) break;
            count += 1;
        }
        return count;
    }

    /**
     * @dev An iterator over resource records.
     */
    struct RRIterator {
        bytes data;
        uint offset;
        uint16 dnstype;
        uint16 class;
        uint32 ttl;
        uint rdataOffset;
        uint nextOffset;
    }

    /**
     * @dev Begins iterating over resource records.
     * @param self The byte string to read from.
     * @param offset The offset to start reading at.
     * @return An iterator object.
     */
    function iterateRRs(bytes memory self, uint offset) internal pure returns (RRIterator memory ret) {
      ret.data = self;
      ret.nextOffset = offset;
      next(ret);
    }

    /**
     * @dev Returns true iff there are more RRs to iterate.
     * @param iter The iterator to check.
     * @return True iff the iterator has finished.
     */
    function done(RRIterator memory iter) internal pure returns(bool) {
      return iter.offset >= iter.data.length;
    }

    /**
     * @dev Moves the iterator to the next resource record.
     * @param iter The iterator to advance.
     */
    function next(RRIterator memory iter) internal pure {
        iter.offset = iter.nextOffset;
        if(iter.offset >= iter.data.length) return;

        // Skip the name
        uint off = iter.offset + nameLength(iter.data, iter.offset);

        // Read type, class, and ttl
        iter.dnstype = iter.data.readUint16(off); off += 2;
        iter.class = iter.data.readUint16(off); off += 2;
        iter.ttl = iter.data.readUint32(off); off += 4;

        // Read the rdata
        uint rdataLength = iter.data.readUint16(off); off += 2;
        iter.rdataOffset = off;
        iter.nextOffset = off + rdataLength;
    }

    /**
     * @dev Returns the name of the current record.
     * @param iter The iterator.
     * @return A new bytes object containing the owner name from the RR.
     */
    function name(RRIterator memory iter) internal pure returns(bytes memory) {
        return iter.data.substring(iter.offset, nameLength(iter.data, iter.offset));
    }

    /**
     * @dev Returns the rdata portion of the current record.
     * @param iter The iterator.
     * @return A new bytes object containing the RR's RDATA.
     */
    function rdata(RRIterator memory iter) internal pure returns(bytes memory) {
        return iter.data.substring(iter.rdataOffset, iter.nextOffset - iter.rdataOffset);
    }

    /**
     * @dev Checks if a given RR type exists in a type bitmap.
     * @param self The byte string to read the type bitmap from.
     * @param offset The offset to start reading at.
     * @param rrtype The RR type to check for.
     * @return True if the type is found in the bitmap, false otherwise.
     */
    function checkTypeBitmap(bytes memory self, uint offset, uint16 rrtype) internal pure returns (bool) {
        uint8 typeWindow = uint8(rrtype >> 8);
        uint8 windowByte = uint8((rrtype & 0xff) / 8);
        uint8 windowBitmask = uint8(uint8(1) << (uint8(7) - uint8(rrtype & 0x7)));
        for(uint off = offset; off < self.length;) {
            uint8 window = self.readUint8(off);
            uint8 len = self.readUint8(off + 1);
            if(typeWindow < window) {
                // We've gone past our window; it's not here.
                return false;
            } else if(typeWindow == window) {
                // Check this type bitmap
                if(len * 8 <= windowByte) {
                    // Our type is past the end of the bitmap
                    return false;
                }

                return (self.readUint8(off + windowByte + 2) & windowBitmask) != 0;
            } else {
                // Skip this type bitmap
                off += len + 2;
            }
        }

        return false;
    }

    function compareNames(bytes memory self, bytes memory other) internal  returns (int){
        int diff = self.compare(other);
        // bool diff;
        // bool diff = (keccak256(self) == keccak256(other));
        // if( !diff ){ return 0; }
        uint sOff = 0;
        uint oOff = 0;

        // // This can be removed if you can pass offset to compare()
        // bytes memory sTail = sTail.substring(sOff, sTail.length - sOff);
        // bytes memory oTail = oTail.substring(oOff, oTail.length - oOff);
        bytes memory sTail = self;
        bytes memory oTail = other;
        bytes memory sHead;
        bytes memory oHead;

        uint sLength = labelCount(self, 0);
        uint oLength = labelCount(other, 0);
        uint counter = 0;
        // while (counter < 5) {
        while (diff != 0) {
        // while ((diff != 0) || (counter < 2)) {
            Logger('Counter');
            LoggerInt(int(counter));
            Logger('Heads');
            if(sLength >= oLength){
                Logger('SSSS');
                sHead = head(self, sOff);
                sOff = progress(self, sOff);
                LoggerBytes(sHead);
                Logger('Before tails');
                LoggerBytes(sTail);
                LoggerInt(int(sOff));
                LoggerInt(int(sTail.length));
                sTail = self.substring(sOff, self.length - sOff);
                Logger('Tails');
                LoggerBytes(sTail);
            }
            if(sLength <= oLength){
                Logger('OOO');
                oHead = head(other, oOff); 
                oOff = progress(other, oOff);
                LoggerBytes(oHead);
                Logger('Before tails');
                LoggerBytes(oTail);
                LoggerInt(int(oOff));
                LoggerInt(int(oTail.length));
                oTail = other.substring(oOff, other.length - oOff);
            }
            Logger('Tails');
            LoggerBytes(sTail);
            LoggerBytes(oTail);

            if(sLength != 0 ){ sLength = labelCount(self, sOff); }
            if(oLength != 0 ){ oLength = labelCount(other, oOff); }
            Logger('soLength');
            LoggerInt(int(sLength));
            LoggerInt(int(oLength));

            if(sLength == 0 && oLength ==0){
                Logger('BREAK');
                break;
            }

            // diff = (keccak256(sTail) == keccak256(oTail));
            diff = sTail.compare(oTail);
            if(diff !=0){
                Logger('diff');
            }else{
                Logger('no diff');
            }

            counter++;
        }
        Logger('Out of loop!!');
        LoggerInt(int(counter));
        LoggerBytes(sHead);
        LoggerBytes(oHead);
        LoggerBytes(sTail);
        LoggerBytes(oTail);

        LoggerInt(int(sHead.compare(oHead)));
        return sHead.compare(oHead);
        // return 0;
    }

    function compareTail(bytes memory self, uint sOff, bytes memory other, uint oOff) internal  returns (int) {
        if(self.length <= sOff &&  other.length <= oOff){ return 0; }

        bytes memory sHead;
        bytes memory oHead;
        if(self.length > sOff){ sHead = head(self, sOff);  }
        if(self.length > oOff){ oHead = head(other, oOff); }
        int result = compareTail(self, sOff + sHead.length + 1, other, oOff + oHead.length + 1);
        if(result == 0){ return sHead.compare(oHead); }
        return result;
    }

    function progress(bytes memory body, uint off) internal  returns(uint){
        Logger('**Off before');
        LoggerInt(int(off));
        uint length = body.readUint8(off);
        LoggerInt(int(length));
        off = off + 1 + length;
        Logger('**Off after');
        LoggerInt(int(off));
        return  off;
    }

    function head(bytes memory body, uint off) internal  returns(bytes){
        return body.substring(off + 1, body.readUint8(off));
    }
}

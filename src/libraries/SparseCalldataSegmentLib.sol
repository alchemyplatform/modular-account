// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {RESERVED_VALIDATION_DATA_INDEX} from "../helpers/Constants.sol";
import {getEmptyCalldataSlice} from "../helpers/EmptyCalldataSlice.sol";

/// @title Sparse Calldata Segment Library
/// @notice Library for working with sparsely-packed calldata segments, identified with an index.
/// @dev The first byte of each segment is the index of the segment.
/// To prevent accidental stack-to-deep errors, the body and index of the segment are extracted separately, rather
/// than inline as part of the tuple returned by `getNextSegment`.
library SparseCalldataSegmentLib {
    error NonCanonicalEncoding();
    error SegmentOutOfOrder();
    error ValidationSignatureSegmentMissing();

    /// @notice Splits out a segment of calldata, sparsely-packed.
    /// The expected format is:
    /// [uint8(index0), uint32(len(segment0)), segment0, uint8(index1), uint32(len(segment1)), segment1,
    /// ... uint8(indexN), uint32(len(segmentN)), segmentN]
    /// @param source The calldata to extract the segment from.
    /// @return segment The extracted segment. Using the above example, this would be segment0.
    /// @return remainder The remaining calldata. Using the above example,
    /// this would start at uint8(index1) and continue to the end at segmentN.
    function getNextSegment(bytes calldata source)
        internal
        pure
        returns (bytes calldata segment, bytes calldata remainder)
    {
        // The first byte of the segment is the index.
        // The next 4 bytes hold the length of the segment, excluding the index.
        uint32 length = uint32(bytes4(source[1:5]));

        // The offset of the remainder of the calldata.
        uint256 remainderOffset = 5 + length;

        // The segment is the next `length` bytes after the first 5 bytes.
        segment = source[5:remainderOffset];

        // The remainder is the rest of the calldata.
        remainder = source[remainderOffset:];
    }

    /// @notice If the index of the next segment in the source equals the provided index, return the next body and
    /// advance the source by one segment.
    /// @dev Reverts if the index of the next segment is less than the provided index, or if the extracted segment
    /// has length 0.
    /// @param source The calldata to extract the segment from.
    /// @param index The index of the segment to extract.
    /// @return A tuple containing the extracted segment's body, or an empty buffer if the index is not found, and
    /// the remaining calldata.
    function advanceSegmentIfAtIndex(bytes calldata source, uint8 index)
        internal
        pure
        returns (bytes calldata, bytes calldata)
    {
        uint8 nextIndex = getIndex(source);

        if (nextIndex < index) {
            revert SegmentOutOfOrder();
        }

        if (nextIndex == index) {
            (bytes calldata segment, bytes calldata remainder) = getNextSegment(source);

            if (segment.length == 0) {
                revert NonCanonicalEncoding();
            }

            return (segment, remainder);
        }

        return (getEmptyCalldataSlice(), source);
    }

    /// @notice Extracts the final segment from the source.
    /// @dev Reverts if the index of the segment is not RESERVED_VALIDATION_DATA_INDEX.
    /// @param source The calldata to extract the segment from.
    /// @return The final segment.
    function getFinalSegment(bytes calldata source) internal pure returns (bytes calldata) {
        if (getIndex(source) != RESERVED_VALIDATION_DATA_INDEX) {
            revert ValidationSignatureSegmentMissing();
        }

        return source[1:];
    }

    /// @notice Extracts the index from a segment.
    /// @dev The first byte of the segment is the index.
    /// @param segment The segment to extract the index from
    /// @return The index of the segment
    function getIndex(bytes calldata segment) internal pure returns (uint8) {
        return uint8(segment[0]);
    }
}

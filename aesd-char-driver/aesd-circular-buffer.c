/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#include <stdio.h>
#endif

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    *entry_offset_byte_rtn = 0; // Resetting output variable to 0
    int index;                  // Index for iterating over buffer entries
    size_t entry_size;          // Size of each buffer entry

    // Check if the buffer is empty
    if (buffer->full == false && (buffer->in_offs == buffer->out_offs))
    {
        return NULL; // Return NULL if the buffer is empty
    }

    // Counter for the number of entries visited during the search
    int entries_visited = 0;

    // Iterate over buffer entries starting from out_offs index
    for (index = buffer->out_offs;
         entries_visited < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
         entries_visited++, index = (index + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
    {
        entry_size = buffer->entry[index].size; // Get the size of the current entry

        if (entry_size <= char_offset)
        {
            // If the offset exceeds the current entry size, move to the next entry
            char_offset -= entry_size;
        }
        else
        {
            // If the entry containing the char_offset is found
            *entry_offset_byte_rtn = char_offset; // Store the offset within the entry
            return &buffer->entry[index]; // Return the found entry
        }
    }

    // If the offset could not be found in any entry
    *entry_offset_byte_rtn = (size_t) - 1;

    // Return NULL if char_offset is beyond the available data
    return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
const char* aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    const char *res = NULL; // Return value to store the pointer to the buffer being overwritten

    // Validate input parameters
    if (!buffer || !add_entry)
    {
        return res; // Return NULL if input parameters are valid
    }

    // Check if the buffer is full
    if (buffer->full)
    {
        // If the buffer is full, prepare to overwrite oldest entry
        res = buffer->entry[buffer->out_offs].buffptr;

        // Move the out_offs index to the next position
        buffer->out_offs = (buffer->out_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    // Add the new entry at the in_offs position
    buffer->entry[buffer->in_offs] = *add_entry;

    // Move the in_offs index to the next position
    buffer->in_offs = (buffer->in_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

    // Check if the buffer is now full
    buffer->full = (buffer->in_offs == buffer->out_offs);

    return res;
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}

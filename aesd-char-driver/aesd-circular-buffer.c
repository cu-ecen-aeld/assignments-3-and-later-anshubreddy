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
    /**
    * TODO: implement per description
    */
    uint8_t current_offset = 0;
    
    if (buffer == NULL || entry_offset_byte_rtn == NULL)
    {
        // Handle invalid input
        return NULL;
    }

    if (buffer->full)
    {
	// In pointer has rolled from end to beginning if we're in full buffer state 
	current_offset = buffer->in_offs;
    }
    else
    {
	// Otherwise, if buffer isn't full, offset is still set by output pointer
	current_offset = buffer->out_offs;
    }

    for (int i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++)
    {
        struct aesd_buffer_entry *entry = &buffer->entry[current_offset];

        if (entry->size == 0)
        {
            // Skip empty entries
            continue;
        }

        if (char_offset < entry->size)
        {
            *entry_offset_byte_rtn = char_offset;
            return entry;
        }
        else
	{
            char_offset -= entry->size;
	    current_offset = (current_offset + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
	}
    }

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
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    /**
    * TODO: implement per description
    */
    if (buffer == NULL || add_entry == NULL)
    {
        // Handle invalid input
        return;
    }

    // Add the new entry at the 'in' position
    buffer->entry[buffer->in_offs] = *add_entry;

    // Advance the 'in' index
    buffer->in_offs = (buffer->in_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

    // Check if buffer is full
    if (buffer->in_offs == buffer->out_offs)
    {
        buffer->full = true;
    }
    else
    {
        buffer->full = false;
    }


    // If the buffer was already full, advance the 'out' index as well
    if (buffer->full)
    {
        buffer->out_offs = (buffer->out_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}

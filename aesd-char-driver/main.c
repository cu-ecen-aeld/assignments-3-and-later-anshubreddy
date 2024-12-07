/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include <linux/uaccess.h> // copy_to_user, copy_from_user
#include <linux/slab.h> // kmalloc, kfree
#include "aesdchar.h"
#include "aesd_ioctl.h"

int aesd_major =   0; // Use dynamic major number
int aesd_minor =   0; // Use dynamic minor number

MODULE_AUTHOR("Anshumaan Reddy");
MODULE_LICENSE("Dual BSD/GPL");

// Device structure
struct aesd_dev aesd_device;

// Handle opening the device file
int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");

    // Retrieve the device structure from the inode structure and assign it
    filp->private_data = container_of(inode->i_cdev, struct aesd_dev, cdev);
    return 0;
}

// Handle closing the device file
int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");

    // Clear the private data
    filp->private_data = NULL;
    return 0;
}

// Handle reading from the device
ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);

    // Retrieve device structure
    struct aesd_dev *dev = filp->private_data;
    if (!dev)
    {
        PDEBUG("Device cannot be accessed");
        return -EINVAL;
    }

    if (!filp || !buf || !f_pos || *f_pos < 0)
    {
        PDEBUG("Invalid arguments");
        return -EINVAL;
    }

    // Lock the device to ensure synchronized access
    retval = mutex_lock_interruptible(&dev->lock);
    if (retval != 0)
    {
        PDEBUG("Unable to lock device mutex");
        return -ERESTARTSYS;
    }

    size_t entry_offset = 0;
    size_t bytes_remaining = 0;

    // Find the entry corresponding to the current file position
    struct aesd_buffer_entry *entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->circular_buffer, *f_pos, &entry_offset);
    if (!entry)
    {
        PDEBUG("Error: Entry for given position not found");
        retval = 0;
        goto unlock;
    }

    bytes_remaining = entry->size - entry_offset;

    // Ensure we do not read more than the requested number of bytes
    if (bytes_remaining > count)
    {
        bytes_remaining = count;
    }

    // Copy data from the kernel buffer to the user buffer
    retval = copy_to_user(buf, entry->buffptr + entry_offset, bytes_remaining);

    if (retval != 0)
    {
        bytes_remaining -= retval;
        PDEBUG("Copying data to user space failed");
        retval = -EFAULT;
        goto unlock;
    }

    // Update file position and return number of bytes read
    *f_pos += bytes_remaining;
    retval = bytes_remaining;

unlock:
    // Unlock the device
    mutex_unlock(&dev->lock);
    PDEBUG("Mutex unlocked");
    return retval;
}

// Handle writing to the device
ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    char *kern_buff = NULL;
    const char *new_ptr = NULL;
    size_t size_until_newline = 0;
    struct aesd_dev *dev = NULL;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);

    if (!filp || !buf || count <= 0 || !f_pos || *f_pos < 0)
    {
        PDEBUG("Invalid arguments");
        return -ENOMEM;
    }

    // Retrieve the device structure
    dev = filp->private_data;
    if (!dev)
    {
        PDEBUG("Device cannot be accessed");
        return -EINVAL;
    }

    // Allocate kernel buffer to store data from user space
    kern_buff = kmalloc(count, GFP_KERNEL);
    if (!kern_buff)
    {
        PDEBUG("Unable to allocate memory");
        return -ENOMEM; // Return error if memory allocation fails
    }

    // Copy data from user space to kernel buffer
    retval = copy_from_user(kern_buff, buf, count);
    if (retval)
    {
        PDEBUG("Unable to copy data from user space");
        retval = -EFAULT; // Return error if copy_from_user fails
        goto free_kern;
    }

    // Find the newline character in the buffer
    new_ptr = memchr(kern_buff, '\n', count);
    size_until_newline = new_ptr ? new_ptr - kern_buff + 1 : 0;

    // Lock the device mutex
    retval = mutex_lock_interruptible(&dev->lock);
    if (retval != 0)
    {
        retval = -ERESTARTSYS;
        PDEBUG("Unable to lock device mutex");
        goto free_kern;
    }

    // If a newline is found, add the entry to the circular buffer
    if (size_until_newline > 0)
    {
        dev->entry.buffptr = krealloc(dev->entry.buffptr, dev->entry.size + size_until_newline, GFP_KERNEL);
        if (!dev->entry.buffptr)
        {
            PDEBUG("Reallocation failed");
            retval = -ENOMEM;
            goto free_unlock;
        }

        // Copy data to the buffer entry
        memcpy(dev->entry.buffptr + dev->entry.size, kern_buff, size_until_newline);
        dev->entry.size += size_until_newline;

        PDEBUG("Adding entry to buffer: size_until_newline = %zu", size_until_newline);
        const char *rtrn = aesd_circular_buffer_add_entry(&dev->circular_buffer, &dev->entry);

        // Free old entry if overwritten
        if (rtrn)
        {
            kfree(rtrn);
        }

        // Reset the entry
        dev->entry.size = 0;
        dev->entry.buffptr = NULL;
    }
    else
    {
        // If no newline, append the data to the current buffer entry
        dev->entry.buffptr = krealloc(dev->entry.buffptr, dev->entry.size + count, GFP_KERNEL);
        if (!dev->entry.buffptr)
        {
            PDEBUG("Reallocation failed");
            retval = -ENOMEM;
            goto free_unlock;
        }

        // Copy data to the buffer entry
        memcpy(dev->entry.buffptr + dev->entry.size, kern_buff, count);
        dev->entry.size += count;
    }

    PDEBUG("Updated entry: size = %zu", dev->entry.size);
    retval = count;

free_unlock:
    // Unlock the device mutex
    mutex_unlock(&dev->lock);
free_kern:
    // Free the kernel buffer
    kfree(kern_buff);
    return retval; // Return number of bytes written
}

// Handle seeking within the device
loff_t aesd_llseek(struct file *filp, loff_t off, int whence)
{
    struct aesd_dev *dev = filp->private_data;
    loff_t newpos;
    int total_size = 0;

    // Determine the new file position based on the whence parameter
    switch(whence)
    {
        // Set the file position to the specified offset
        case SEEK_SET:
            newpos = off;
            break;

        // Set the file position relative to the current position
        case SEEK_CUR:
            newpos = filp->f_pos + off;
            break;

        // Set the file position relative to the end of the file
        case SEEK_END:
            if (mutex_lock_interruptible(&dev->lock) != 0)
            {
                PDEBUG("Error: Unable to do mutex lock");
                return -ERESTARTSYS;
            }

            // Calculate the total length
            for (int i = dev->circular_buffer.out_offs; i != dev->circular_buffer.in_offs; )
            {
                total_size += dev->circular_buffer.entry[i].size;
                i = (i + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
            }
            newpos = total_size - 1 + off;
            mutex_unlock(&dev->lock);
            break;

        default:
            // Invalid whence parameter, hence, return an error
            return -EINVAL;
    }

    // Ensure the new file position is within valid bounds
    if (newpos < 0)
    {
        return -EINVAL;
    }

    // Update the file position
    mutex_lock(&dev->lock);
    filp->f_pos = newpos;
    PDEBUG("Sought file position to %d", newpos);
    mutex_unlock(&dev->lock);

    return newpos;
}

// Handle ioctl commands
long aesd_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct aesd_dev *dev = filp->private_data;
    struct aesd_seekto seekto;
    int total_size = 0;
    long ret = 0;

    PDEBUG("ioctl command %u", cmd);

    // Check if the command is AESDCHAR_IOCSEEKTO
    if (cmd != AESDCHAR_IOCSEEKTO)
    {
        PDEBUG("Invalid inputs for aesd_unlocked_ioctl\n");
        ret = -ENOTTY; // Not a valid IOCTL command for this driver
        goto quit;
    }

    // Copy the seekto structure from user space
    if (copy_from_user(&seekto, (struct aesd_seekto __user *) arg, sizeof(seekto)))
    {
        PDEBUG("Failed to copy from user space\n");
        ret = -EFAULT; // Return error if copy from user space fails
        goto quit;
    }

    // Validate the write_cmd value
    if (seekto.write_cmd >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED || seekto.write_cmd < 0)
    {
        PDEBUG("Error: Invalid command index %u", seekto.write_cmd);
        ret = -EINVAL; // Return error if write_cmd is invalid
        goto quit;
    }

    // seekto.write_cmd = (seekto.write_cmd + dev->circular_buffer.out_offs) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    PDEBUG("Write cmd is %u, write cmd offset is %u", seekto.write_cmd, seekto.write_cmd_offset);

    if (seekto.write_cmd_offset >= dev->circular_buffer.entry[seekto.write_cmd].size)
    {
        PDEBUG("Error: Invalid command offset %u for entry size %zu", seekto.write_cmd_offset, dev->circular_buffer.entry[seekto.write_cmd].size);
        ret = -EINVAL; // Return error if write_cmd offset is invalid
        goto quit;
    }

    // Lock the mutex to ensure synchronized access to the device
    ret = mutex_lock_interruptible(&dev->lock);
    if (ret != 0)
    {
        PDEBUG("Unable to lock mutex");
        ret = -ERESTARTSYS; // Return error if locking fails
        goto quit;
    }

    // Calculate the new file position based on the write_cmd and write_cmd_offset
    for (int i = dev->circular_buffer.out_offs; i != seekto.write_cmd;)
    {
        total_size += dev->circular_buffer.entry[i].size; // Add the size of the entry to newpos
        i = (i + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    filp->f_pos = total_size + seekto.write_cmd_offset; // Update the file position
    mutex_unlock(&dev->lock);
    PDEBUG("Total size is %d", total_size);
    PDEBUG("Updated file position to %lld", filp->f_pos);

quit:
    return ret;
}

// File operations structure
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read           = aesd_read,
    .write          = aesd_write,
    .open           = aesd_open,
    .release        = aesd_release,
    .llseek         = aesd_llseek,
    .unlocked_ioctl = aesd_unlocked_ioctl,
};

// Setup character device
static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    // Initialize character device
    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;

    // Add character device to the system
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}

// Module initialization function
int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;

    // Allocate major and minor numbers
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }

    // Initialize device structure
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    // Initialize mutex and circular buffer
    aesd_circular_buffer_init(&aesd_device.circular_buffer);
    mutex_init(&aesd_device.lock);

    // Setup character device
    result = aesd_setup_cdev(&aesd_device);

    if (result)
    {
        unregister_chrdev_region(dev, 1); // Clean up on error
    }

    return result;
}

// Module cleanup function
void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    // Remove character device
    cdev_del(&aesd_device.cdev);

    struct aesd_buffer_entry *entry;
    uint8_t index = 0;
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.circular_buffer, index);
    {
        if (entry->buffptr != NULL)
        {
            kfree(entry->buffptr);
        }
    }

    // Cleanup mutex
    mutex_destroy(&aesd_device.lock);

    // Unregister major and minor numbers
    unregister_chrdev_region(devno, 1);
}

// Register module initialization and cleanup functions
module_init(aesd_init_module);
module_exit(aesd_cleanup_module);

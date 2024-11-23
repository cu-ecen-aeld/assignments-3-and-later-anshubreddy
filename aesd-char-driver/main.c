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

    if (!filp || !buf || !f_pos)
    {
        PDEBUG("Invalid arguments");
        return -EINVAL;
    }

    int res = mutex_lock_interruptible(&dev->lock);
    if (res != 0)
    {
        PDEBUG("Unable to lock device mutex");
        return -ERESTARTSYS;
    }

    size_t entry_offset = 0;
    size_t bytes_to_read = count;
    struct aesd_buffer_entry *entry;
    size_t total_bytes_read = 0;

    while (bytes_to_read > 0)
    {
        // Find the entry in the circular buffer corresponding to the file position
        entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->circular_buffer, *f_pos, &entry_offset);

        if (!entry)
        {
            PDEBUG("Error: Entry for given position not found. f_pos: %lld", *f_pos);
            retval = 0;
            goto unlock;
        }

        size_t bytes_remaining = entry->size - entry_offset;
        size_t bytes_this_read = bytes_remaining > bytes_to_read ? bytes_to_read : bytes_remaining;

        // Copy data from the circular buffer to the user buffer
        unsigned long bytes_not_copied = copy_to_user(buf + total_bytes_read, entry->buffptr + entry_offset, bytes_this_read);
        if (bytes_not_copied != 0)
        {
            PDEBUG("Unable to do user-kernel copy");
            retval = -EFAULT;
            goto unlock;
        }

        total_bytes_read += bytes_this_read;
        *f_pos += bytes_this_read;
        bytes_to_read -= bytes_this_read;
    }

    retval = total_bytes_read;

unlock:
    mutex_unlock(&dev->lock);
    return retval;
}

// Handle writing to the device
ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);

    if (!filp || !buf || !f_pos)
    {
        PDEBUG("Invalid arguments");
        return -ENOMEM;
    }

    // Allocate kernel buffer to store data from user space
    char *kern_buff = kmalloc(count, GFP_KERNEL);
    if (!kern_buff)
    {
        PDEBUG("Unable to allocate memory");
        return -ENOMEM; // Return error if memory allocation fails
    }

    // Copy data from user space to kernel buffer
    unsigned long bytes_not_copied = copy_from_user(kern_buff, buf, count);
    if (bytes_not_copied != 0)
    {
        PDEBUG("Unable to copy data from user space");
        kfree(kern_buff); // Free allocated memory on failure
        return -EFAULT; // Return error if copy_from_user fails
    }

    // Retrieve the device structure
    struct aesd_dev *dev = filp->private_data;
    if (!dev)
    {
        PDEBUG("Device cannot be accessed");
        kfree(kern_buff);
        return -EINVAL;
    }

    // Lock the device mutex
    int res = mutex_lock_interruptible(&dev->lock);
    if (res != 0)
    {
        PDEBUG("Unable to lock device mutex");
        kfree(kern_buff);
        return -ERESTARTSYS;
    }

    // Create a new buffer entry
    PDEBUG("Appending %zu bytes to temporary entry buffer", count);
    size_t old_size = dev->tmp_entry.size;
    dev->tmp_entry.size += count;
    char *new_entry_loc = krealloc(dev->tmp_entry.buffptr, dev->tmp_entry.size, GFP_KERNEL);

    if (!new_entry_loc)
    {
        PDEBUG("Unable to reallocate memory\n");
        kfree(kern_buff);
        mutex_unlock(&dev->lock);
        return -ENOMEM;
    }

    dev->tmp_entry.buffptr = new_entry_loc;
    memcpy(dev->tmp_entry.buffptr + old_size, kern_buff, count);

    // Add entry to circular buffer
    if (memchr(kern_buff, '\n', count) != NULL)
    {
        PDEBUG("Newline found. Adding entry to circular buffer.");
        aesd_circular_buffer_add_entry(&dev->circular_buffer, &dev->tmp_entry);

        if (dev->circular_buffer.full)
        {
            struct aesd_buffer_entry *old_entry = &dev->circular_buffer.entry[dev->circular_buffer.out_offs];
            kfree(old_entry->buffptr);
        }

        dev->tmp_entry.size = 0;
        dev->tmp_entry.buffptr = NULL;
    }

    retval = count;
    mutex_unlock(&dev->lock);
    kfree(kern_buff);

    // Return number of bytes written
    return retval;
}

// File operations structure
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
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

    memset(&aesd_device,0,sizeof(struct aesd_dev)); // Initialize device structure

    // Initialize mutex and circular buffer
    mutex_init(&aesd_device.lock);
    aesd_circular_buffer_init(&aesd_device.circular_buffer);

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

    // Cleanup mutex
    mutex_destroy(&aesd_device.lock);

    // Unregister major and minor numbers
    unregister_chrdev_region(devno, 1);
}

// Register module initialization and cleanup functions
module_init(aesd_init_module);
module_exit(aesd_cleanup_module);

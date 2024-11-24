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

    if (!filp || !buf || !f_pos || *f_pos < 0)
    {
        PDEBUG("Invalid arguments");
        return -EINVAL;
    }

    retval = mutex_lock_interruptible(&dev->lock);
    if (retval != 0)
    {
        PDEBUG("Unable to lock device mutex");
        return -ERESTARTSYS;
    }

    size_t entry_offset = 0;
    size_t bytes_remaining = 0;

    struct aesd_buffer_entry *entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->circular_buffer, *f_pos, &entry_offset);
    if (!entry)
    {
        PDEBUG("Error: Entry for given position not found");
        retval = 0;
        goto unlock;
    }

    bytes_remaining = entry->size - entry_offset;

    if (bytes_remaining > count)
    {
        bytes_remaining = count;
    }

    retval = copy_to_user(buf, entry->buffptr + entry_offset, bytes_remaining);

    if (retval != 0)
    {
        bytes_remaining -= retval;
        PDEBUG("Copying data to user space failed");
        retval = -EFAULT;
        goto unlock;
    }

    *f_pos += bytes_remaining;
    retval = bytes_remaining;

unlock:
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
    const char *newline_ptr = NULL;
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
        goto free_mem_exit;
    }

    newline_ptr = memchr(kern_buff, '\n', count);
    size_until_newline = newline_ptr ? newline_ptr - kern_buff + 1 : 0;

    // Lock the device mutex
    retval = mutex_lock_interruptible(&dev->lock);
    if (retval != 0)
    {
        retval = -ERESTARTSYS;
        PDEBUG("Unable to lock device mutex");
        goto free_mem_exit;
    }

    if (size_until_newline > 0)
    {
        dev->entry.buffptr = krealloc(dev->entry.buffptr, dev->entry.size + size_until_newline, GFP_KERNEL);
        if (!dev->entry.buffptr)
        {
            PDEBUG("Reallocation failed");
            retval = -ENOMEM;
            goto free_unlock_exit;
        }

        memcpy(dev->entry.buffptr + dev->entry.size, kern_buff, size_until_newline);
        dev->entry.size += size_until_newline;

        aesd_circular_buffer_add_entry(&dev->circular_buffer, &dev->entry);

        dev->entry.size = 0;
        dev->entry.buffptr = NULL;
    }
    else
    {
        dev->entry.buffptr = krealloc(dev->entry.buffptr, dev->entry.size + count, GFP_KERNEL);
        if (!dev->entry.buffptr)
        {
            PDEBUG("Reallocation failed");
            retval = -ENOMEM;
            goto free_unlock_exit;
        }

        memcpy(dev->entry.buffptr + dev->entry.size, kern_buff, count);
        dev->entry.size += count;
    }

    retval = count;

free_unlock_exit:
    mutex_unlock(&dev->lock);
free_mem_exit:
    kfree(kern_buff);
    return retval; // Return number of bytes written
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

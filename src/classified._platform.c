#include <Python.h>

#ifdef PLATFORM_DARWIN
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#include <sys/resource.h>
#endif

#ifdef PLATFORM_LINUX2
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <mntent.h>

#endif

#ifdef PLATFORM_OPENBSD5
#include <sys/param.h>
#include <sys/mount.h>
#endif

#include "classified._platform.h"

enum {
    PRIORITY_REALTIME,
    PRIORITY_NORMAL,
    PRIORITY_IDLE,
};

static char get_filesystems_docstring[] = \
    "Get a list of mounted file systems";
static PyObject *get_filesystems(PyObject *self, PyObject *args) {
#if defined(PLATFORM_DARWIN) || defined(PLATFORM_OPENBSD5)
    PyObject *result = NULL;
    PyObject *mountpoint = NULL;

    struct statfs *mntbuf = NULL;
    int mntsize = 0, n = 0;
    #if defined(PLATFORM_DARWIN)
    int bufsize = 0;
    #elif defined(PLATFORM_OPENBSD5)
    /* Probably also works on FreeBSD, DragonFly and NetBSD */
    long bufsize = 0;
    #endif

    /* determine the number of active mount points */
    mntsize = getfsstat(NULL, 0, MNT_NOWAIT);
    if (mntsize > 0) {
        bufsize = (mntsize + 4) * sizeof(*mntbuf);
        mntbuf = (struct statfs *) malloc(bufsize);
        result = PyTuple_New(mntsize);
        //assert(PyTuple_Check(result));

        /* determine the mount point for the device file */
        mntsize = getfsstat(mntbuf, bufsize, MNT_NOWAIT);
        for (n = 0; n < mntsize; ++n) {
            mountpoint = (PyObject *) PyDict_New();
            PyDict_SetItemString(mountpoint, "device",
                PyString_FromString(mntbuf[n].f_mntfromname));
            PyDict_SetItemString(mountpoint, "mount",
                PyString_FromString(mntbuf[n].f_mntonname));
            PyDict_SetItemString(mountpoint, "type",
                PyString_FromString(mntbuf[n].f_fstypename));
            PyTuple_SetItem(result, n, mountpoint);
            Py_INCREF(mountpoint);
        }

        return result;
    } else {
        Py_INCREF(Py_None);
        return Py_None;
    }
#elif defined(PLATFORM_LINUX2)
    PyObject *result, *mountpoint;

    FILE* mtab = NULL;
    struct mntent* m;
    struct mntent mnt;
    char strings[4096];
    struct statfs fs;
    int n = 0;

    // First count the number of availabel file systems, is there any nicer way
    // of doing this?
    if ((mtab = setmntent("/etc/mtab", "r")) != NULL) {
        while ((m = getmntent_r(mtab, &mnt, strings, sizeof(strings))) != NULL) {
            if ((mnt.mnt_dir != NULL) && (statfs(mnt.mnt_dir, &fs) == 0)) {
                ++n;
            }
        }
        endmntent(mtab);
    }

    if (n == 0) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    result = (PyObject *) PyTuple_New(n);
    //assert(PyTuple_Check(result));

    n = 0;
    if ((mtab = setmntent("/etc/mtab", "r")) != NULL) {
        while ((m = getmntent_r(mtab, &mnt, strings, sizeof(strings))) != NULL) {
            if ((mnt.mnt_dir != NULL) && (statfs(mnt.mnt_dir, &fs) == 0)) {
                mountpoint = (PyObject *) PyDict_New();
                //assert(PyDict_Check(mountpoint));

                PyDict_SetItemString(mountpoint, "device",
                    PyString_FromString(mnt.mnt_fsname));
                PyDict_SetItemString(mountpoint, "mount",
                    PyString_FromString(mnt.mnt_dir));
                PyDict_SetItemString(mountpoint, "type",
                    PyString_FromString(mnt.mnt_type));
                PyTuple_SetItem(result, n++, mountpoint);
                Py_INCREF(mountpoint);
            }
        }
        endmntent(mtab);
    }

    return result;
#else
    Py_INCREF(Py_None);
    return Py_None;
#endif
}

static char get_ionice_docstring[] = \
    "Get the I/O priority of the current process";
static PyObject *get_ionice(PyObject *self, PyObject *args) {
#if defined(PLATFORM_DARWIN)
    fprintf(stderr, "get_ionice on darwin\n");
    Py_INCREF(Py_None);
    return Py_None;
#elif defined(PLATFORM_LINUX2)
    fprintf(stderr, "get_ionice on linux\n");
    PyObject *result = NULL;
    pid_t pid = getpid();
    int ioprio = ioprio_get(IOPRIO_WHO_PROCESS, pid);
    int ioclass = IOPRIO_PRIO_CLASS(ioprio);
    int priority = -1;

    fprintf(stderr, "get_ionice gave %d / %d\n", ioprio, ioclass);

    switch (ioclass) {
    case IOPRIO_CLASS_NONE:
    case IOPRIO_CLASS_IDLE:
        priority = PRIORITY_IDLE;
        break;
    case IOPRIO_CLASS_BE:
        priority = PRIORITY_NORMAL;
        break;
    case IOPRIO_CLASS_RT:
        priority = PRIORITY_REALTIME;
        break;
    }

    result = PyInt_FromLong(priority);
    return result;
#else
    fprintf(stderr, "get_ionice on unsupported\n");
    Py_INCREF(Py_None);
    return Py_None;
#endif
}

static char set_ionice_docstring[] = \
    "Set the I/O priority of the current process";
static PyObject *set_ionice(PyObject *self, PyObject *args) {
    int priority = -1;
    if (!PyArg_ParseTuple(args, "i", &priority))
        return NULL;

    if (priority < 0 || priority > 3)
        return NULL;

    fprintf(stderr, "set_ionice with %d\n", priority);

#if defined(PLATFORM_LINUX2)
    pid_t pid = getpid();
    int ioclass = 0, data = 4;

    switch (priority) {
    case PRIORITY_IDLE:
        fprintf(stderr, "set to IDLE\n");
        ioclass = IOPRIO_CLASS_IDLE;
        data = 0;
        break;
    case PRIORITY_NORMAL:
        fprintf(stderr, "set to BE\n");
        ioclass = IOPRIO_CLASS_BE;
        break;
    case PRIORITY_REALTIME:
        fprintf(stderr, "set to RT\n");
        ioclass = IOPRIO_CLASS_RT;
        data = 7;
        break;
    }

    ioprio_set(IOPRIO_WHO_PROCESS, pid,
        IOPRIO_PRIO_VALUE(ioclass, data));

    Py_INCREF(Py_True);
    return Py_True;
#else
    Py_INCREF(Py_None);
    return Py_None;
#endif
}

static char module_docstring[] = \
    "This module provides platform specific operations.";
static PyMethodDef module_methods[] = {
    {"get_filesystems", get_filesystems, METH_NOARGS,
        get_filesystems_docstring},
    {"get_ionice", get_ionice, METH_NOARGS,
        get_ionice_docstring},
    {"set_ionice", set_ionice, METH_VARARGS,
        set_ionice_docstring},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC init_platform(void)
{
    PyObject *m = Py_InitModule3("_platform", module_methods, module_docstring);
    PyObject *d = PyModule_GetDict(m);
    PyObject *tmp;

    if (m == NULL)
        return;
    if (d == NULL)
        return;

    tmp = PyInt_FromLong(PRIORITY_NORMAL);
    PyDict_SetItemString(d, "PRIORITY_NORMAL", tmp);
    Py_DECREF(tmp);
    tmp = PyInt_FromLong(PRIORITY_IDLE);
    PyDict_SetItemString(d, "PRIORITY_IDLE", tmp);
    Py_DECREF(tmp);
    tmp = PyInt_FromLong(PRIORITY_REALTIME);
    PyDict_SetItemString(d, "PRIORITY_REALTIME", tmp);
    Py_DECREF(tmp);
}


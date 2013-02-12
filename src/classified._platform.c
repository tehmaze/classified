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

static char module_docstring[] = \
    "This module provides platform specific operations.";
static PyMethodDef module_methods[] = {
    {"get_filesystems", get_filesystems, METH_NOARGS,
        get_filesystems_docstring},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC init_platform(void)
{
    PyObject *m = Py_InitModule3("_platform", module_methods, module_docstring);
    PyObject *d = PyModule_GetDict(m);

    if (m == NULL)
        return;
    if (d == NULL)
        return;
}


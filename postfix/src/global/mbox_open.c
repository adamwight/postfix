/*++
/* NAME
/*	mbox_open 3
/* SUMMARY
/*	mailbox access
/* SYNOPSIS
/*	#include <mbox_open.h>
/*
/*	typedef struct {
/* .in +4
/*		/* public members... */
/*		VSTREAM	*fp;
/* .in -4
/*	} MBOX;
/*
/*	MBOX	*mbox_open(path, flags, mode, st, user, group, lock_style, why)
/*	const char *path;
/*	int	flags;
/*	int	mode;
/*	struct stat *st;
/*	uid_t	user;
/*	gid_t	group;
/*	int	lock_style;
/*	DSN_VSTRING *why;
/*
/*	void	mbox_release(mbox)
/*	MBOX	*mbox;
/*
/*	const char *mbox_dsn(err)
/*	int	err;
/* DESCRIPTION
/*	This module manages access to UNIX mailbox-style files.
/*
/*	mbox_open() acquires exclusive access to the named file.
/*	The \fBpath, flags, mode, st, user, group, why\fR arguments
/*	are passed to the \fBsafe_open\fR() routine. Attempts to change
/*	file ownership will succeed only if the process runs with
/*	adequate effective privileges.
/*	The \fBlock_style\fR argument specifies a lock style from
/*	mbox_lock_mask(). Locks are applied to regular files only.
/*	The result is a handle that must be destroyed by mbox_release().
/*
/*	mbox_release() releases the named mailbox. It is up to the
/*	application to close the stream.
/*
/*	mbox_dsn() translates an errno value to a mailbox related
/*	DSN detail code.
/* DIAGNOSTICS
/*	mbox_open() returns a null pointer in case of problems, and
/*	sets errno to EAGAIN if someone else has exclusive access.
/*	Other errors are likely to have a more permanent nature.
/* LICENSE
/* .ad
/* .fi
/*	The Secure Mailer license must be distributed with this software.
/* AUTHOR(S)
/*	Wietse Venema
/*	IBM T.J. Watson Research
/*	P.O. Box 704
/*	Yorktown Heights, NY 10598, USA
/*--*/

/* System library. */

#include <sys_defs.h>
#include <sys/stat.h>
#include <errno.h>

#ifndef EDQUOT
#define EDQUOT EFBIG
#endif

/* Utility library. */

#include <msg.h>
#include <vstream.h>
#include <vstring.h>
#include <safe_open.h>
#include <iostuff.h>
#include <mymalloc.h>

/* Global library. */

#include <dot_lockfile.h>
#include <deliver_flock.h>
#include <mbox_conf.h>
#include <mbox_open.h>

/* mbox_open - open mailbox-style file for exclusive access */

MBOX   *mbox_open(const char *path, int flags, int mode, struct stat * st,
		          uid_t chown_uid, gid_t chown_gid,
		          int lock_style, DSN_VSTRING *why)
{
    struct stat local_statbuf;
    MBOX   *mp;
    int     locked = 0;
    VSTREAM *fp;

    /*
     * Open or create the target file. In case of a privileged open, the
     * privileged user may be attacked with hard/soft link tricks in an
     * unsafe parent directory. In case of an unprivileged open, the mail
     * system may be attacked by a malicious user-specified path, or the
     * unprivileged user may be attacked with hard/soft link tricks in an
     * unsafe parent directory. Open non-blocking to fend off attacks
     * involving non-file targets.
     * 
     * We open before locking, so that we can avoid attempts to dot-lock
     * destinations such as /dev/null.
     */
    if (st == 0)
	st = &local_statbuf;
    if ((fp = safe_open(path, flags | O_NONBLOCK, mode, st,
			chown_uid, chown_gid, why->vstring)) == 0) {
	dsn_vstring_update(why, mbox_dsn(errno), "");
	return (0);
    }
    close_on_exec(vstream_fileno(fp), CLOSE_ON_EXEC);

    /*
     * If this is a regular file, create a dotlock file. This locking method
     * does not work well over NFS, but it is better than some alternatives.
     * With NFS, creating files atomically is a problem, and a successful
     * operation can fail with EEXIST.
     * 
     * If filename.lock can't be created for reasons other than "file exists",
     * issue only a warning if the application says it is non-fatal. This is
     * for bass-awkward compatibility with existing installations that
     * deliver to files in non-writable directories.
     * 
     * Alternatively, we could dot-lock the file before opening, but then we
     * would be doing silly things like dot-locking /dev/null, something that
     * an unprivileged user is not supposed to be able to do.
     */
    if (S_ISREG(st->st_mode) && (lock_style & MBOX_DOT_LOCK)) {
	if (dot_lockfile(path, why->vstring) == 0) {
	    locked |= MBOX_DOT_LOCK;
	} else if (errno == EEXIST) {
	    dsn_vstring_update(why, mbox_dsn(EAGAIN), "");
	    vstream_fclose(fp);
	    return (0);
	} else if (lock_style & MBOX_DOT_LOCK_MAY_FAIL) {
	    msg_warn("%s", vstring_str(why->vstring));
	} else {
	    dsn_vstring_update(why, mbox_dsn(errno), "");
	    vstream_fclose(fp);
	    return (0);
	}
    }

    /*
     * If this is a regular file, acquire kernel locks. flock() locks are not
     * intended to work across a network; fcntl() locks are supposed to work
     * over NFS, but in the real world, NFS lock daemons often have serious
     * problems.
     */
#define HUNKY_DORY(lock_mask, myflock_style) ((lock_style & (lock_mask)) == 0 \
         || deliver_flock(vstream_fileno(fp), (myflock_style), why->vstring) == 0)

    if (S_ISREG(st->st_mode)) {
	if (HUNKY_DORY(MBOX_FLOCK_LOCK, MYFLOCK_STYLE_FLOCK)
	    && HUNKY_DORY(MBOX_FCNTL_LOCK, MYFLOCK_STYLE_FCNTL)) {
	    locked |= lock_style;
	} else {
	    dsn_vstring_update(why, mbox_dsn(errno), "");
	    if (locked & MBOX_DOT_LOCK)
		dot_unlockfile(path);
	    vstream_fclose(fp);
	    return (0);
	}
    }
    mp = (MBOX *) mymalloc(sizeof(*mp));
    mp->path = mystrdup(path);
    mp->fp = fp;
    mp->locked = locked;
    return (mp);
}

/* mbox_release - release mailbox exclusive access */

void    mbox_release(MBOX *mp)
{

    /*
     * Unfortunately we can't close the stream, because on some file systems
     * (AFS), the only way to find out if a file was written successfully is
     * to close it, and therefore the close() operation is in the mail_copy()
     * routine. If we really insist on owning the vstream member, then we
     * should export appropriate methods that mail_copy() can use in order
     * to manipulate a message stream.
     */
    if (mp->locked & MBOX_DOT_LOCK)
	dot_unlockfile(mp->path);
    myfree(mp->path);
    myfree((char *) mp);
}

/* mbox_dsn - map errno value to mailbox-related DSN detail */

const char *mbox_dsn(int err)
{
#define TRY_AGAIN_ERROR(e) \
	(e == EACCES || e == EAGAIN || e == ESTALE)
#define SYSTEM_FULL_ERROR(e) \
	(e == ENOSPC)
#define MBOX_FULL_ERROR(e) \
	(e == EDQUOT || e == EFBIG)

    return (TRY_AGAIN_ERROR(err) ? "4.2.0" :
	    SYSTEM_FULL_ERROR(err) ? "4.3.0" :
	    MBOX_FULL_ERROR(err) ? "5.2.2" :
	    "5.2.0");
}

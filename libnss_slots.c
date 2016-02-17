#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>

#include <nss.h>
#include <pwd.h>
#include <grp.h>

#define SLOT_COUNT (10000)
#define SLOT_UID_LO (20000)
#define SLOT_UID_HI (SLOT_UID_LO + 10000)

#define SLOT_OK_UID(uid) ((SLOT_UID_LO <= uid) && (uid < SLOT_UID_HI))
#define SLOT_OK(slot) ((0 <= slot) && (slot < SLOT_COUNT))
#define SLOT_OK_NAME(name) (strlen(name) == 5 && name[0] == 's' && isdigit(name[1]) && isdigit(name[2]) && isdigit(name[3]) && isdigit(name[4]))
#define SLOT_TO_UID(slot) (SLOT_UID_LO + slot)
#define SLOT_OF_UID(uid) (uid - SLOT_UID_LO)

////////////
// PASSWD //
////////////

enum nss_status fill_passwd(struct passwd* pwbuf, char* buf, size_t buflen, struct passwd entry, int* errnop) {
    int name_length = strlen(entry.pw_name) + 1;
    int pw_length = strlen(entry.pw_passwd) + 1;
    int gecos_length = strlen(entry.pw_gecos) + 1;
    int homedir_length = strlen(entry.pw_dir) + 1;
    int shell_length = strlen(entry.pw_shell) + 1;

    int total_length = name_length + pw_length + gecos_length + shell_length + homedir_length;

    if(buflen < total_length) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    pwbuf->pw_uid = entry.pw_uid;
    pwbuf->pw_gid = entry.pw_gid;

    strcpy(buf, entry.pw_name);
    pwbuf->pw_name = buf;
    buf += name_length;

    strcpy(buf, entry.pw_passwd);
    pwbuf->pw_passwd = buf;
    buf += pw_length;

    strcpy(buf, entry.pw_gecos);
    pwbuf->pw_gecos = buf;
    buf += gecos_length;

    strcpy(buf, entry.pw_dir);
    pwbuf->pw_dir = buf;
    buf += homedir_length;

    strcpy(buf, entry.pw_shell);
    pwbuf->pw_shell = buf;

    return NSS_STATUS_SUCCESS;
}

enum nss_status slots_fill_passwd(struct passwd *pwbuf, char *buf, size_t buflen, int slot_id, int *errnop) {
    struct passwd entry;
    char name_buf[10];

    if (!SLOT_OK(slot_id)) {
        return NSS_STATUS_NOTFOUND;
    }

    sprintf(name_buf, "s%04d", slot_id);
    entry.pw_uid = SLOT_TO_UID(slot_id);
    entry.pw_gid = SLOT_TO_UID(slot_id);
    entry.pw_name = name_buf;
    entry.pw_passwd = "x";
    entry.pw_gecos = "";
    entry.pw_dir = "/";
    entry.pw_shell = "/bin/false";
    return fill_passwd(pwbuf, buf, buflen, entry, errnop);
}

enum nss_status _nss_slots_getpwuid_r(uid_t uid, struct passwd *pwbuf, char *buf, size_t buflen, int *errnop) {
    if (!SLOT_OK_UID(uid)) {
        return NSS_STATUS_NOTFOUND;
    }
    return slots_fill_passwd(pwbuf, buf, buflen, SLOT_OF_UID(uid), errnop);
}

enum nss_status _nss_slots_getpwnam_r(const char *name, struct passwd *pwbuf, char *buf, size_t buflen, int *errnop) {
    if (!SLOT_OK_NAME(name)) {
        return NSS_STATUS_NOTFOUND;
    }
    int slot_id = strtol(name + 1, NULL, 10);
    return slots_fill_passwd(pwbuf, buf, buflen, slot_id, errnop);
}

///////////
// GROUP //
///////////

enum nss_status slots_fill_group(struct group *grbuf, char *buf, size_t buflen, int slot_id, int *errnop) {

    if (!SLOT_OK(slot_id)) {
        return NSS_STATUS_NOTFOUND;
    }

    int name_length = 6;
    int pw_length = 2;
    int mem_length = sizeof(char*);
    int total_length = name_length + pw_length + mem_length;

    if (buflen < total_length) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    grbuf->gr_gid = SLOT_TO_UID(slot_id);

    sprintf(buf, "s%04d", slot_id);
    grbuf->gr_name = buf;
    buf += name_length;

    strcpy(buf, "x");
    grbuf->gr_passwd = buf;
    buf += pw_length;

    *((char**)buf) = NULL;
    grbuf->gr_mem = (char**)buf;

    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_slots_getgrgid_r(gid_t gid, struct group *grbuf, char *buf, size_t buflen, int *errnop) {
    if (!SLOT_OK_UID(gid)) {
        return NSS_STATUS_NOTFOUND;
    }
    return slots_fill_group(grbuf, buf, buflen, SLOT_OF_UID(gid), errnop);
}

enum nss_status _nss_slots_getgrnam_r(const char *name, struct group *grbuf, char *buf, size_t buflen, int *errnop) {
    if (!SLOT_OK_NAME(name)) {
        return NSS_STATUS_NOTFOUND;
    }
    int slot_id = strtol(name + 1, NULL, 10);
    return slots_fill_group(grbuf, buf, buflen, slot_id, errnop);
}

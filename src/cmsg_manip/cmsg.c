// Need to use GNU_SOURCE for ucred struct
#define _GNU_SOURCE
#include <sys/socket.h>

size_t cmsghdr_size = sizeof(struct cmsghdr);
size_t iovec_size = sizeof(struct iovec);
size_t msghdr_size = sizeof(struct msghdr);
size_t ucred_size = sizeof(struct ucred);

int scm_credentials = SCM_CREDENTIALS;
int scm_rights = SCM_RIGHTS;
int so_passcred = SO_PASSCRED;

int msg_eor = MSG_EOR;
int msg_trunc = MSG_TRUNC;
int msg_ctrunc = MSG_CTRUNC;
int msg_errqueue = MSG_ERRQUEUE;
int msg_dontwait = MSG_DONTWAIT;
int msg_cmsg_cloexec = MSG_CMSG_CLOEXEC;
int msg_nosignal = MSG_NOSIGNAL;
int msg_peek = MSG_PEEK;
int msg_waitall = MSG_WAITALL;

struct cmsghdr * cmsg_firsthdr(struct msghdr *msgh) {
    return CMSG_FIRSTHDR(msgh);
}

struct cmsghdr * cmsg_nxthdr(struct msghdr *msgh, struct cmsghdr *cmsg) {
    return CMSG_NXTHDR(msgh, cmsg);
}

size_t cmsg_align(size_t length) {
    return CMSG_ALIGN(length);
}

size_t cmsg_space(size_t length) {
    return CMSG_SPACE(length);
}

size_t cmsg_len(size_t length) {
    return CMSG_LEN(length);
}

unsigned char * cmsg_data(struct cmsghdr *cmsg) {
    return CMSG_DATA(cmsg);
}

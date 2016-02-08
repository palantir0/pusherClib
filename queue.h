#ifndef __QUEUE_H__
#define __QUEUE_H__

#include <stdlib.h>
#include <stdio.h>
#include "sglib.h"
#include "semaphore.h"
#include "errno.h"


struct QueueElement {
    void   *data;
    struct QueueElement *nextPtr;
};

struct Queue {
    struct QueueElement **elements;
    int size;
    int head;
    int freeHead;
    sem_t   lock;
};


//SGLIB_DEFINE_QUEUE_FUNCTIONS(struct Queue, struct QueueElement, elements, head, freeHead, MAX_PARAMS);

extern struct Queue *sgCreateQueue(int noofElements);
extern int sgEnqueue(struct Queue *q, void *data);
extern int sgDequeue(struct Queue *q, void **data);

#endif

    /**
     * A synchronized version of queues based upon SGLIB.
     */
#include "queue.h"

#define MAX_QUEUE_DEPTH     20

struct Queue *
sgCreateQueue(int noofElements) {
    struct Queue *q = (struct Queue *)calloc(1, sizeof(struct Queue));
    if (!q)
        return NULL;
    q->elements = (struct QueueElement **)calloc(1, sizeof(struct QueueElement *) * noofElements);
    if (q->elements == NULL) {
        free(q);
        return NULL;
    }
    q->size = noofElements;

    SGLIB_QUEUE_INIT(struct QueueElement *, q->elements, q->head, q->freeHead);

    sem_init(&q->lock, 1, 1);
    return q;
}

static inline struct QueueElement *
sgAllocElement() {
    return (struct QueueElement *)calloc(sizeof(struct QueueElement), 1);
}


static inline void 
sgFreeElement(struct QueueElement *qe) {
    free(qe);
}

int 
sgEnqueue(struct Queue *q, void *data) {
    sem_wait(&q->lock);
    if (SGLIB_QUEUE_IS_FULL(struct QueueElement *, q->elements, q->head, q->freeHead, q->size)) {
        sem_post(&q->lock);
        printf("queue is full\n");
        return -1;
    }
    struct QueueElement *qelem = sgAllocElement();
    if (qelem == NULL) {
        printf("Out of memory\n");
        return -ENOMEM;
    }
    qelem->data = data;
    SGLIB_QUEUE_ADD(struct QueueElement *, q->elements, qelem, q->head, q->freeHead, q->size);
    sem_post(&q->lock);
    return 0;
}

int 
sgDequeue(struct Queue *q, void **data) {
    struct QueueElement *qelem;
    sem_wait(&q->lock);
    if (SGLIB_QUEUE_IS_EMPTY(struct QueueElement *, q->elements, q->head, q->freeHead)) {
        *data = NULL;
        sem_post(&q->lock);
        printf("queue is empty\n");
        return -1;
    }
    qelem = SGLIB_QUEUE_FIRST_ELEMENT(struct QueueElement *, q->elements, q->head, q->freeHead);
    SGLIB_QUEUE_DELETE(struct QueueElement *, q->elements, q->head, q->freeHead, q->size);
    sem_post(&q->lock);

    if (qelem != NULL) {
        *data = qelem->data;
        sgFreeElement(qelem);
    }
    return 0;
}




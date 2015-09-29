/*
 * Generic list data type
 * Copyright (c) 2001,2004 David H. Hovemeyer <daveho@cs.umd.edu>
 * Copyright (c) 2003,2013,2014 Jeffrey K. Hollingsworth <hollings@cs.umd.edu>
 *
 * All rights reserved.
 *
 * This code may not be resdistributed without the permission of the copyright holders.
 * Any student solutions using any of this code base constitute derviced work and may
 * not be redistributed in any form.  This includes (but is not limited to) posting on
 * public forums or web sites, providing copies to (past, present, or future) students
 * enrolled in similar operating systems courses the University of Maryland's CMSC412 course.
 *
 */

#ifndef GEEKOS_LIST_H
#define GEEKOS_LIST_H

#include <geekos/ktypes.h>
#include <geekos/kassert.h>
#include <geekos/lock.h>

#define Unlock_List(lock)		Spin_Unlock(lock)
#define Lock_List(lock)			Spin_Lock(lock)

/*
 * Define a list type.
 */
#define DEFINE_LIST(listTypeName, nodeTypeName)		\
struct listTypeName {					\
    struct nodeTypeName *head, *tail;			\
    Spin_Lock_t lock;					\
}

/*
 * Define members of a struct to be used as link fields for
 * membership in given list type.
 */
#define DEFINE_LINK(listTypeName, nodeTypeName) \
    struct nodeTypeName * prev##listTypeName, * next##listTypeName

/*
 * Define inline list manipulation and access functions.
 */
#define IMPLEMENT_LIST(LType, NType)								\
static __inline__ void Clear_##LType(struct LType *listPtr) {					\
    listPtr->head = listPtr->tail = 0;								\
}												\
static __inline__ bool Is_Member_Of_##LType(struct LType *listPtr, struct NType *nodePtr) {	\
    Lock_List(&listPtr->lock);										\
    struct NType *cur = listPtr->head;								\
    while (cur != 0) {										\
	if (cur == nodePtr) {									\
	    Unlock_List(&listPtr->lock);									\
	    return true;									\
        }											\
	cur = cur->next##LType;									\
    }												\
    Unlock_List(&listPtr->lock);										\
    return false;										\
}static __inline__ bool Is_Member_Of2_##LType(struct LType *listPtr, struct NType *nodePtr) {    \
    Lock_List(&listPtr->lock);                                      \
    struct NType *cur = listPtr->head;\
    int j=0;                              \
    while (cur != 0) {                                      \
    if (cur == nodePtr && j==1) {                   \
            j++;                                   \
        Unlock_List(&listPtr->lock);                                    \
        return true;                                    \
        }                                           \
    cur = cur->next##LType;                                 \
    }                                               \
    Unlock_List(&listPtr->lock);                                        \
    return false;                                       \
}												\
static __inline__ struct NType * Get_Front_Of_##LType(struct LType *listPtr) {			\
    return listPtr->head;									\
}												\
static __inline__ struct NType * Get_Back_Of_##LType(struct LType *listPtr) {			\
    return listPtr->tail;									\
}												\
static __inline__ struct NType * Get_Next_In_##LType(struct NType *nodePtr) {			\
    return nodePtr->next##LType;								\
}												\
static __inline__ void Set_Next_In_##LType(struct NType *nodePtr, struct NType *value) {	\
    nodePtr->next##LType = value;								\
}												\
static __inline__ struct NType * Get_Prev_In_##LType(struct NType *nodePtr) {			\
    return nodePtr->prev##LType;								\
}												\
static __inline__ void Set_Prev_In_##LType(struct NType *nodePtr, struct NType *value) {	\
    nodePtr->prev##LType = value;								\
}												\
static __inline__ void Add_To_Front_Of_##LType(struct LType *listPtr, struct NType *nodePtr) {	\
    KASSERT(!Is_Member_Of_##LType(listPtr, nodePtr));						\
    Lock_List(&listPtr->lock);										\
    nodePtr->prev##LType = 0;									\
    if (listPtr->head == 0) {									\
	listPtr->head = listPtr->tail = nodePtr;						\
	nodePtr->next##LType = 0;								\
    } else {											\
	listPtr->head->prev##LType = nodePtr;							\
	nodePtr->next##LType = listPtr->head;							\
	listPtr->head = nodePtr;								\
    }												\
    Unlock_List(&listPtr->lock);										\
}												\
static __inline__ void Unchecked_Add_To_Back_Of_##LType(struct LType *listPtr, struct NType *nodePtr) {	\
    nodePtr->next##LType = 0;									\
    Lock_List(&listPtr->lock); 									\
    if (listPtr->tail == 0) {									\
	listPtr->head = listPtr->tail = nodePtr;						\
	nodePtr->prev##LType = 0;								\
    } else {											\
	listPtr->tail->next##LType = nodePtr;							\
	nodePtr->prev##LType = listPtr->tail;							\
	listPtr->tail = nodePtr;								\
    }												\
    Unlock_List(&listPtr->lock);										\
}												\
static __inline__ void Add_To_Back_Of_##LType(struct LType *listPtr, struct NType *nodePtr) {	\
    KASSERT(!Is_Member_Of_##LType(listPtr, nodePtr));						\
    Unchecked_Add_To_Back_Of_##LType(listPtr, nodePtr);						\
}												\
static __inline__ void Append_##LType(struct LType *listToModify, struct LType *listToAppend) {	\
    Lock_List(&listToModify->lock);										\
    Lock_List(&listToAppend->lock);										\
    if (listToAppend->head != 0) {								\
	if (listToModify->head == 0) {								\
	    listToModify->head = listToAppend->head;						\
	    listToModify->tail = listToAppend->tail;						\
	} else {										\
	    KASSERT(listToAppend->head != 0);							\
	    KASSERT(listToModify->tail != 0);							\
	    listToAppend->head->prev##LType = listToModify->tail;				\
	    listToModify->tail->next##LType = listToAppend->head;				\
	    listToModify->tail = listToAppend->tail;						\
	}											\
    }												\
    listToAppend->head = listToAppend->tail = 0;						\
    Unlock_List(&listToAppend->lock);										\
    Unlock_List(&listToModify->lock);										\
}												\
static __inline__ struct NType * Remove_From_Front_Of_##LType(struct LType *listPtr) {		\
    Lock_List(&listPtr->lock);										\
    struct NType *nodePtr;									\
    nodePtr = listPtr->head;									\
    KASSERT(nodePtr != 0);									\
    listPtr->head = listPtr->head->next##LType;							\
    if (listPtr->head == 0)									\
	listPtr->tail = 0;									\
    else											\
	listPtr->head->prev##LType = 0;								\
    Unlock_List(&listPtr->lock);										\
    return nodePtr;										\
}												\
static __inline__ void Remove_From_##LType(struct LType *listPtr, struct NType *nodePtr) {	\
    KASSERT(Is_Member_Of_##LType(listPtr, nodePtr));						\
    Lock_List(&listPtr->lock);										\
    if (nodePtr->prev##LType != 0)								\
	nodePtr->prev##LType->next##LType = nodePtr->next##LType;				\
    else											\
	listPtr->head = nodePtr->next##LType;							\
    if (nodePtr->next##LType != 0)								\
	nodePtr->next##LType->prev##LType = nodePtr->prev##LType;				\
    else											\
	listPtr->tail = nodePtr->prev##LType;							\
    Unlock_List(&listPtr->lock);										\
}												\
static __inline__ bool Is_##LType##_Empty(struct LType *listPtr) {				\
    return listPtr->head == 0;									\
} \
static __inline__ void Insert_Into_##LType(struct LType *listPtr, struct NType *nodeToInsertAfter, struct NType *nodePtr) { \
    KASSERT(Is_Member_Of_##LType(listPtr, nodeToInsertAfter));	\
    Lock_List(&listPtr->lock);										\
    if(nodeToInsertAfter->next##LType == 0) {				    \
      nodeToInsertAfter->next##LType = nodePtr;                 \
      nodePtr->prev##LType = nodeToInsertAfter;                 \
      nodePtr->next##LType = 0;                                 \
      listPtr->tail = nodePtr;                                  \
    }                                                           \
    else {                                                      \
      nodePtr->next##LType = nodeToInsertAfter->next##LType;	\
      nodeToInsertAfter->next##LType = nodePtr;                 \
      nodePtr->prev##LType = nodeToInsertAfter;                 \
      nodePtr->next##LType->prev##LType = nodePtr;              \
    }                                                           \
    Unlock_List(&listPtr->lock);										\
}
#endif /* GEEKOS_LIST_H */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include "ldapexpr.h"
#include "srcip_filter.h"
#include "srcport_filter.h"
#include "dstip_filter.h"
#include "dstport_filter.h"
#include "protocol.h"

#define  BUFFER_LEN       64

struct filter_ctrl_ {
    enum {
        FT_EQ,		/* = */
        FT_NE,		/* != */
        FT_LT,		/* < */
        FT_GT,		/* > */
        FT_LTE,		/* <= */
        FT_GTE,		/* >= */

        FT_AND,		/* 复合过滤器 & */
        FT_OR,		/* 复合过滤器 | */
        FT_NOT,		/* 复合过滤器 ! */
    } type;

    union {
        struct {
            struct filter_ctrl_ *left;
            struct filter_ctrl_ *right;
        } m;		/* 复合过滤器时使用 */
        struct {
            char *subject;
            char *value;
        } s;		/* 非复合过滤时使用 */
    };
};


typedef struct handle_list_ {
    char *key;
    void *user;
    filter_cmp_handler hander;
    struct handle_list_ *next;

} handle_list_st;

static handle_list_st *g_handle_header = NULL;

static const char *s_ft_tab[] = {
    "=",
    "!=",
    "<",
    ">",
    "<=",
    ">=",
    "and",
    "or",
    "not",
};


static int opr2type(const char *opr)
{
    if (strcmp(opr, "=") == 0)
        return FT_EQ;

    if (strcmp(opr, "!=") == 0)
        return FT_NE;

    if (strcmp(opr, "<") == 0)
        return FT_LT;

    if (strcmp(opr, ">") == 0)
        return FT_GT;

    if (strcmp(opr, "<=") == 0)
        return FT_LTE;

    if (strcmp(opr, ">=") == 0)
        return FT_GTE;

    return -1;
}

static filter_ctrl_st *filter_create_(int ft)
{
    filter_ctrl_st *ret = calloc(1, sizeof(filter_ctrl_st));
    assert(ret);

    ret->type = ft;
    return ret;
}

static void filter_destroy_(filter_ctrl_st *filt)
{
    if (!filt)
        return;

    if (filt->type == FT_AND || filt->type == FT_OR || filt->type == FT_NOT) {
        filter_destroy_(filt->m.left);
        filter_destroy_(filt->m.right);
    }
    else {
        free(filt->s.subject);
        free(filt->s.value);
    }

    free(filt);
}

/* 处理txt，起始位置为*pos，完成后*pos应指向未parse的新位置 */
static filter_ctrl_st *filter_parse_(const char *txt, uint32_t *pos)
{
    filter_ctrl_st *ret = NULL;
    char subject[128];
    char value[128];
    char opr[16];

    /* 所有filter都是(开始 */
    if (txt[*pos] != '(') {
        fprintf(stderr, "Filter expect a '('\n");
        return NULL;
    }

    (*pos)++;
    switch (txt[*pos]) {
    case '&':
    case '|':
        /* (&(X)(Y)) and or表过式第一个字符为&|，后面带两个子表达式，递归处理并赋值到left/right */
        ret = filter_create_(txt[*pos] == '&' ? FT_AND : FT_OR);

        (*pos)++;

        ret->m.left = filter_parse_(txt, pos);
        if (!ret->m.left)
            goto failed;

        ret->m.right = filter_parse_(txt, pos);
        if (!ret->m.right)
            goto failed;

        break;
    case '!':
        /* (!(X)) not表达式第一个字符为!，后面带一个子表达式，存于left */
        ret = filter_create_(FT_NOT);

        (*pos)++;

        ret->m.left = filter_parse_(txt, pos);
        if (!ret->m.left)
            goto failed;

        break;
    default:
        /* (subject?=value) 普通表达式，简单地使用sscanf获取数据 */
        if (sscanf(txt + *pos, "%127[^=!<>()\n ]%15[=!<>]%127[^)]", subject, opr, value) != 3) {
            fprintf(stderr, "Filter format error\n");
            goto failed;
        }

        int type = opr2type(opr);
        if (type < 0) {
            fprintf(stderr, "Filter operator not supported: %s\n", opr);
            goto failed;
        }

        /* 定位到当前表达式的)处 */
        const char *end = strchr(txt + *pos, ')');
        if (!end) {
            fprintf(stderr, "Filter is not closed with ')'\n");
            goto failed;
        }

        ret = filter_create_(type);
        ret->s.subject = strdup(subject);
        ret->s.value = strdup(value);

        /* 更新*pos为)的位置 */
        *pos = (end - txt);
        break;
    }

    /* 所有filter都是)结束 */
    if (txt[*pos] != ')') {
        fprintf(stderr, "Filter expect a '('\n");
        goto failed;
    }
    (*pos)++;
    return ret;

failed:
    filter_destroy(ret);
    return NULL;
}

filter_ctrl_st *filter_parse(const char *txt)
{
    uint32_t pos = 0;
    filter_ctrl_st *filt = filter_parse_(txt, &pos);

    if (txt[pos] != 0) {
        fprintf(stderr, "Unexpected %s\n", txt + pos);
        filter_destroy_(filt);
        return NULL;
    }

    return filt;
}

/* 过滤器注册条件模块
*/
int filter_register_module(const char *key, filter_cmp_handler handler, void *user)
{
    if (NULL == key || NULL == handler) {
        fprintf(stderr, "error param\n");
        return -1;
    }
    handle_list_st *handle = (handle_list_st *)malloc(sizeof(handle_list_st));
    if (NULL == handle) {
        fprintf(stderr, "malloc fail\n");
        return -1;
    }
    //补充检查遍历key冲突流程
    handle->key = (char *)malloc(strlen(key) + 1);
    if (NULL == handle->key) {
        fprintf(stderr, "malloc fail\n");
        return -1;
    }
    strncpy(handle->key, key, strlen(key));
    handle->hander = handler;
    handle->user = user;
    if (NULL == g_handle_header) {
        g_handle_header = handle;
        return 0;
    }
    handle_list_st *tmp = g_handle_header;
    while(tmp->next) {
        tmp = tmp->next;
    }
    tmp->next = handle;
    return 0;
}

static handle_list_st *filter_find_module(const char *key)
{
    if (NULL == key)
        return NULL;
    handle_list_st *cur = g_handle_header;
    while (cur) {
        if (strncmp(cur->key, key, strlen(key)) == 0)
            break;
        cur = cur->next;
    }
    return cur;
}

/* 过滤器注销条件模块*/
void filter_unregister_module(const char *key)
{
    if (NULL == key) {
        fprintf(stderr, "the key is null\n");
        return;
    }
    if (NULL == g_handle_header) {
        fprintf(stderr, "g_handle_header is null\n");
        return;
    }
    handle_list_st *cur = g_handle_header;
    handle_list_st *prev = NULL;
    while (cur) {
        if (strncmp(cur->key, key, strlen(key)) == 0) {
            break;
        }

        prev = cur;
        cur = cur->next;
    }
    if (cur == NULL) {
        fprintf(stderr, "cur is null\n");
        return;
    }
    if (prev == NULL) {
        /*证明头结点是匹配key值*/
        g_handle_header = cur->next;
    } else {
        prev->next = cur->next;
    }
    if (cur->key) {
        free(cur->key);
        cur->key = NULL;
    }
    free(cur);
    cur = NULL;
}

/*提供api层 使用 parse */
filter_ctrl_st *filter_create(const char *expr)
{
    filter_ctrl_st *filt = filter_parse(expr);

    if (srcip_register_filter() != 0) {
        fprintf(stderr,"srcip filter register fail\n");
        return NULL;
    }
    if (srcport_register_filter() != 0) {
        fprintf(stderr,"srcport filter register fail\n");
        return NULL;
    }
    if (dstport_register_filter() != 0) {
        fprintf(stderr,"dstport filter register fail\n");
        return NULL;
    }
    if (dstip_register_filter() != 0) {
        fprintf(stderr,"dstip filter register fail\n");
        return NULL;
    }
    if (protocal_register_filter() != 0) {
        fprintf(stderr,"dstip filter register fail\n");
        return NULL;
    }
    return filt;
}

void filter_destroy(filter_ctrl_st *filter)
{
    if (filter) {
        srcip_unregister_filter();
        srcport_unregister_filter();
        dstport_unregister_filter();
        srcport_unregister_filter();
        protocal_unregister_filter();
        filter_destroy_(filter);
    }
}

/** 过滤器输入数据 匹配规则 **/
int filter_check_packet(filter_ctrl_st *filter, pcap_packet_st *packet)
{
    if (NULL == filter || NULL == packet) {
        fprintf(stderr,"error param\n");
        return 0;
    }
    if (filter->type == FT_AND ) {
        return filter_check_packet(filter->m.left, packet) &&
               filter_check_packet(filter->m.right, packet);
    } else if (filter->type == FT_OR) {
        return filter_check_packet(filter->m.left, packet) ||
               filter_check_packet(filter->m.right, packet);
    } else if (filter->type == FT_NOT) {
        return !filter_check_packet(filter->m.left, packet);
    } else {
        handle_list_st *cur = filter_find_module(filter->s.subject);
        if (NULL == cur)
            return 0;
        return cur->hander(packet, filter, cur->user);
    }
}

const char *filter_get_name(filter_ctrl_st *filter)
{
    if (NULL == filter) {
        return NULL;
    }

    return filter->s.subject;
}

int filter_check_string(filter_ctrl_st *filter, char *str)
{
    if (NULL == filter || NULL == str) {
        fprintf(stderr,"error param\n");
        return 0;
    }
    switch (filter->type)
    {
    case FT_EQ:
        return strncmp(filter->s.value, str, strlen(filter->s.value)) == 0;
    case FT_NE:
        return strncmp(filter->s.value, str, strlen(filter->s.value)) != 0;
    default:
        fprintf(stderr,"unsupport type \n");
        break;
    }
    return 0;
}

int filter_check_uint(filter_ctrl_st *filter, uint32_t number)
{
    if (NULL == filter) {
        fprintf(stderr,"error param\n");
        return 0;
    }
    unsigned int expr_num = strtouq(filter->s.value, NULL, 10);
    switch (filter->type)
    {
    case FT_EQ:
        return number == expr_num;
    case FT_NE:
        return number != expr_num;
    case FT_LT:
        return number < expr_num;
    case FT_GT:
        return number > expr_num;
    case FT_LTE:
        return number <= expr_num;
    case FT_GTE:
        return number >= expr_num;
    default:
        fprintf(stderr,"unknown filter type\n");
        break;
    }
    return 0;
}

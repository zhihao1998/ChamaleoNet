#include "tsdn.h"

static PyObject *pModule, *pClass, *pInstance;
static table_entry_t **p4_entry_buf;
static circular_buf_t *p4_entry_circ_buf;
static pthread_mutex_t entry_install_mutex;
static pthread_cond_t entry_install_cond;
char ip_src_addr_str[INET_ADDRSTRLEN], ip_dst_addr_str[INET_ADDRSTRLEN];
static service_hash_t **service_hash_table;

u_long entry_circ_buf_size()
{
#ifdef SWITCH_ENABLED
	return circular_buf_size(p4_entry_circ_buf);
#else
	return 0;
#endif
}

u_long hash_func_service(in_addr service_ip, ushort service_port, ushort service_protocol)
{
	u_long hval = 0;
	hval = (service_ip.s_addr + service_port + service_protocol) % ENTRY_HASH_TABLE_SIZE;
	return hval;
}

static service_hash_t *CreateServiceHash(in_addr service_ip, ushort service_port, ushort service_protocol)
{
	service_hash_t *new_service_hash_ptr, *service_hash_head_ptr;

	new_service_hash_ptr = service_hash_alloc();
	new_service_hash_ptr->service_ip = service_ip;
	new_service_hash_ptr->service_port = service_port;
	new_service_hash_ptr->service_protocol = service_protocol;
	new_service_hash_ptr->hash = hash_func_service(service_ip, service_port, service_protocol);

	service_hash_head_ptr = service_hash_table[new_service_hash_ptr->hash];
	if (service_hash_head_ptr == NULL)
	{
		service_hash_table[new_service_hash_ptr->hash] = new_service_hash_ptr;
		new_service_hash_ptr->prev = NULL;
		new_service_hash_ptr->next = service_hash_head_ptr;
	}
	else
	{
		/* it is not the first entry in the slot, insert it to the head  */
		new_service_hash_ptr->prev = NULL;
		new_service_hash_ptr->next = service_hash_head_ptr;

		service_hash_head_ptr->prev = new_service_hash_ptr;
		service_hash_table[new_service_hash_ptr->hash] = new_service_hash_ptr;
	}

	return new_service_hash_ptr;
}

static service_hash_t *FindServiceHash(in_addr service_ip, ushort service_port, ushort service_protocol)
{
	hash hval;
	service_hash_t *service_hash_head_ptr, *service_hash_ptr;

	hval = hash_func_service(service_ip, service_port, service_protocol);
	service_hash_head_ptr = service_hash_table[hval];

	if (service_hash_head_ptr == NULL)
	{
		return NULL;
	}

	for (service_hash_ptr = service_hash_head_ptr; service_hash_ptr; service_hash_ptr = service_hash_ptr->next)
	{
		if (service_hash_ptr->service_ip.s_addr == service_ip.s_addr &&
			service_hash_ptr->service_port == service_port &&
			service_hash_ptr->service_protocol == service_protocol)
		{
			return service_hash_ptr;
		}
	}

	return NULL;
}

int try_install_p4_entry(in_addr service_ip, ushort service_port, ushort service_protocol)
{

	service_hash_t *service_hash_ptr;
	table_entry_t *temp_table_entry_ptr, **temp_table_entry_pp;

	service_hash_ptr = FindServiceHash(service_ip, service_port, service_protocol);
	// If there is already a service hash entry, then return
	if (service_hash_ptr != NULL)
	{
		return 0;
	}
	// If there is no service hash entry, then create one
	else
	{
		service_hash_ptr = CreateServiceHash(service_ip, service_port, service_protocol);
		temp_table_entry_ptr = table_entry_alloc();
		temp_table_entry_ptr->service_ip = service_ip;
		temp_table_entry_ptr->service_port = service_port;
		temp_table_entry_ptr->service_protocol = service_protocol;
	}

	if (temp_table_entry_ptr != NULL)
	{
		fprintf(fp_log, "active,%s,%d,%d\n",
				inet_ntop(AF_INET, &temp_table_entry_ptr->service_ip, ip_src_addr_str, INET_ADDRSTRLEN),
				temp_table_entry_ptr->service_port, temp_table_entry_ptr->service_protocol);

		temp_table_entry_pp = (table_entry_t **)circular_buf_try_put(p4_entry_circ_buf, (void *)temp_table_entry_ptr);
		// fprintf(fp_log, "Adding (ip: %s ,port: %d, protocol: %d) to the entry buffer, size: %ld, head: %ld, tail: %ld\n",
		// 		inet_ntop(AF_INET, &temp_table_entry_ptr->internal_ip, ip_src_addr_str, INET_ADDRSTRLEN),
		// 		temp_table_entry_ptr->internal_port, temp_table_entry_ptr->protocol, entry_circ_buf_size(), p4_entry_circ_buf->head, p4_entry_circ_buf->tail);
	}

	assert(temp_table_entry_pp != NULL);

	pthread_cond_signal(&entry_install_cond);
	return 0;
}

void *install_thead_main(void *args)
{
#ifdef SWITCH_ENABLED
	/* Initialize the P4 entry buffer */
	p4_entry_buf = (table_entry_t **)MallocZ(ENTRY_BUF_SIZE * sizeof(table_entry_t *));
	p4_entry_circ_buf = circular_buf_init((void **)p4_entry_buf, ENTRY_BUF_SIZE);

	/* Initialize hash table for service */
	service_hash_table = (service_hash_t **)MallocZ(ENTRY_HASH_TABLE_SIZE * sizeof(service_hash_t *));

	bfrt_grpc_init();
	PyGILState_STATE ret = PyGILState_Ensure();
	pthread_mutex_init(&entry_install_mutex, NULL);
	pthread_cond_init(&entry_install_cond, NULL);

	timeval start_time, end_time;
	active_host_tbl_entry_count = 0;

	while (circular_buf_empty(p4_entry_circ_buf))
	{
		printf("Waiting for drop entry\n");
		pthread_cond_wait(&entry_install_cond, &entry_install_mutex);
	}

	while (1)
	{
		void *buf_slot;
		if (circular_buf_empty(p4_entry_circ_buf))
		{
			pthread_cond_wait(&entry_install_cond, &entry_install_mutex);
		}

#ifdef DO_STATS
		// gettimeofday(&start_time, NULL);
#endif

		if (circular_buf_get(p4_entry_circ_buf, &buf_slot) != -1)
		{
			int res;
			table_entry_t *table_entry_ptr = (table_entry_t *)buf_slot;
			// fprintf(fp_log, "Installing (ip: %s ,port: %d, protocol: %d) to the entry buffer, size: %ld, head: %ld, tail: %ld\n",
			// 		inet_ntop(AF_INET, &table_entry_ptr->internal_ip, ip_src_addr_str, INET_ADDRSTRLEN),
			// 		table_entry_ptr->internal_port, table_entry_ptr->protocol, entry_circ_buf_size(), p4_entry_circ_buf->head, p4_entry_circ_buf->tail);
			assert(table_entry_ptr != NULL);

			res = bfrt_active_host_tbl_add_with_drop(table_entry_ptr->service_ip, table_entry_ptr->service_port, table_entry_ptr->service_protocol);

			table_entry_release(table_entry_ptr);

#ifdef DO_STATS
			installed_entry_count_tot += res;
			switch (table_entry_ptr->service_protocol)
			{
			case IPPROTO_TCP:
			{
				installed_entry_count_tcp += res;
				break;
			}
			case IPPROTO_UDP:
			{
				installed_entry_count_udp += res;
			}
			case IPPROTO_ICMP:
			{
				installed_entry_count_icmp += res;
				break;
			}
			}
		}
#endif

#ifdef DO_STATS
		// gettimeofday(&end_time, NULL);
		// printf("entry_adding_time: %d\n", tv_sub_2(end_time, start_time));
#endif
		if (elapsed(last_idle_cleaned_time, current_time) > ENTRY_IDLE_TIMEOUT)
		{
			gettimeofday(&start_time, NULL);
			clean_all_idle_entries();
			last_idle_cleaned_time = current_time;
			gettimeofday(&end_time, NULL);
			printf("cleaning time: %d\n", tv_sub_2(end_time, start_time));
		}
#ifdef DO_STATS
		// gettimeofday(&end_time, NULL);
		// printf("cleaning time: %d\n", tv_sub_2(end_time, start_time));
#endif

#ifdef DO_STATS
		active_host_tbl_entry_count = bfrt_get_table_usage("active_host_tbl");

		// gettimeofday(&end_time, NULL);
		// printf("get_table_entry_num_time: %d\n", tv_sub_2(end_time, start_time));
#endif
	}
	PyGILState_Release(ret);
#endif /* SWITCH_ENABLED */
	return NULL;
}

int clean_all_idle_entries()
{
	assert(pInstance != NULL);
	PyObject *pArgs, *pRes, *pFunc;
	int ret = -1;

	pFunc = PyObject_GetAttrString(pInstance, "clean_all_idle_entries");
	pArgs = Py_BuildValue("()");
	pRes = PyEval_CallObject(pFunc, pArgs);
	// PyArg_Parse(pRes, "i", &ret);
	Py_DECREF(pFunc);
	Py_DECREF(pArgs);
	Py_DECREF(pRes);
	return ret;
}

void bfrt_clear_tables()
{
	PyObject *pArgs, *pRes, *pFunc;
	pFunc = PyObject_GetAttrString(pInstance, "clear_tables");
	pArgs = Py_BuildValue("()");
	pRes = PyEval_CallObject(pFunc, pArgs);
	Py_DECREF(pFunc);
	Py_DECREF(pArgs);
	Py_DECREF(pRes);
}

/* Initialze Grpc object */
void bfrt_grpc_init()
{
	PyObject *pArgs;
	Py_Initialize();
	PyEval_InitThreads();

	PyRun_SimpleString("import sys");
	PyRun_SimpleString("sys.path.append('./bfrt_grpc')");

	pModule = PyImport_ImportModule("bfrt_grpc_client");
	assert(pModule != NULL);
	/* Call Py_INCREF() for objects that you want to keep around for a while.
	 * A pointer to an object that has been INCREFed is said to be protected. */
	Py_INCREF(pModule);

	pClass = PyObject_GetAttrString(pModule, "Bfrt_GRPC_Client"); /* fetch module.class */
	assert(pClass != NULL);
	Py_INCREF(pClass);

	/* Instantiate the class */
	pArgs = Py_BuildValue("()"); /* create empty argument tuple */
	pInstance = PyEval_CallObject(pClass, pArgs);
	assert(pInstance != NULL);
	Py_INCREF(pInstance);

	bfrt_clear_tables();
}

int bfrt_grpc_destroy()
{
	/* Clean up */
	if (pInstance == NULL || pClass == NULL || pModule == NULL)
	{
		return -1;
	}
	// assert(pInstance != NULL);
	// assert(pClass != NULL);
	// assert(pModule != NULL);

	Py_DECREF(pInstance);
	Py_DECREF(pClass);
	Py_DECREF(pModule);
	Py_Finalize();
	return 0;
}

/* TCP Flow Table */
int bfrt_active_host_tbl_add_with_drop(in_addr internal_ip, u_short internal_port, u_short ip_protocol)
{
	assert(pInstance != NULL);
	PyObject *pArgs, *pRes, *pFunc;
	char ip_addr_str[INET_ADDRSTRLEN];
	int ret = 0;

	inet_ntop(AF_INET, &(internal_ip), ip_addr_str, INET_ADDRSTRLEN);

	pFunc = PyObject_GetAttrString(pInstance, "internal_host_add_with_drop");
	pArgs = Py_BuildValue("(sii)", ip_addr_str, ntohs(internal_port), ip_protocol);
	pRes = PyEval_CallObject(pFunc, pArgs);
	assert(pRes != NULL);
	PyArg_Parse(pRes, "i", &ret);
	Py_DECREF(pFunc);
	Py_DECREF(pArgs);
	Py_DECREF(pRes);
	return ret;
}

/* Get Entry Table Number */
int bfrt_get_table_usage(char *table_name)
{
	assert(pInstance != NULL);
	PyObject *pArgs, *pRes, *pFunc;
	int ret = -1;

	pFunc = PyObject_GetAttrString(pInstance, "get_table_usage");
	pArgs = Py_BuildValue("(s)", table_name);
	pRes = PyEval_CallObject(pFunc, pArgs);
	PyArg_Parse(pRes, "i", &ret);
	Py_DECREF(pFunc);
	Py_DECREF(pArgs);
	Py_DECREF(pRes);
	return ret;
}

int bfrt_print_tables_info()
{
	assert(pInstance != NULL);
	PyObject *pArgs, *pRes, *pFunc;
	int ret = -1;

	pFunc = PyObject_GetAttrString(pInstance, "print_tables_info");
	pArgs = Py_BuildValue("()");
	pRes = PyEval_CallObject(pFunc, pArgs);
	// PyArg_Parse(pRes, "i", &ret);
	Py_DECREF(pFunc);
	Py_DECREF(pArgs);
	Py_DECREF(pRes);
	return ret;
}

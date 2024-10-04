#include "tsdn.h"

static PyObject *pModule, *pClass, *pInstance;
static table_entry_t **p4_entry_buf;
static circular_buf_t *p4_entry_circ_buf;
static table_entry_t *temp_table_entry_ptr;
static pthread_mutex_t entry_install_mutex;
static pthread_cond_t entry_install_cond;

u_long entry_circ_buf_size()
{
	return circular_buf_size(p4_entry_circ_buf);
}

int try_install_drop_entry(in_addr src_ip, in_addr dst_ip, ushort src_port, u_short dst_port, ushort protocol)
{
	static table_entry_t **temp_table_entry_pp;
	temp_table_entry_ptr->src_ip = src_ip;
	temp_table_entry_ptr->dst_ip = dst_ip;
	temp_table_entry_ptr->src_port = src_port;
	temp_table_entry_ptr->dst_port = dst_port;
	temp_table_entry_ptr->protocol = protocol;
	temp_table_entry_pp = (table_entry_t **)circular_buf_try_put(p4_entry_circ_buf, (void *)temp_table_entry_ptr);
	assert(temp_table_entry_pp != NULL);

	pthread_cond_signal(&entry_install_cond);
	return 0;
}

void *install_drop_entry(void *args)
{
	void *buf_slot;
	p4_entry_buf = (table_entry_t **)MallocZ(ENTRY_BUF_SIZE * sizeof(table_entry_t *));
	p4_entry_circ_buf = circular_buf_init((void **)p4_entry_buf, ENTRY_BUF_SIZE);
	temp_table_entry_ptr = (table_entry_t *)MallocZ(sizeof(table_entry_t));

	timeval start_time, end_time;

	char ip_src_addr_str[INET_ADDRSTRLEN], ip_dst_addr_str[INET_ADDRSTRLEN];
	bfrt_grpc_init();
	PyGILState_STATE ret = PyGILState_Ensure();
	pthread_mutex_init(&entry_install_mutex, NULL);
	pthread_cond_init(&entry_install_cond, NULL);

	tcp_flow_entry_count = udp_flow_entry_count = icmp_flow_entry_count = 0;

	while (circular_buf_empty(p4_entry_circ_buf))
	{
		fprintf(fp_log, "Waiting for drop entry\n");
		pthread_cond_wait(&entry_install_cond, &entry_install_mutex);
	}

	while (1)
	{
		if (circular_buf_empty(p4_entry_circ_buf))
		{
			pthread_cond_wait(&entry_install_cond, &entry_install_mutex);
		}

		/* Check the next timeout */
#ifdef DO_STATS
		gettimeofday(&start_time, NULL);
#endif

		if (circular_buf_get(p4_entry_circ_buf, &buf_slot) != -1)
		{
			int res;
			table_entry_t *table_entry_ptr = (table_entry_t *)buf_slot;
			assert(table_entry_ptr != NULL);

			inet_ntop(AF_INET, &(table_entry_ptr->src_ip), ip_src_addr_str, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(table_entry_ptr->dst_ip), ip_dst_addr_str, INET_ADDRSTRLEN);

			switch (table_entry_ptr->protocol)
			{
			case IPPROTO_TCP:
			{
				res = bfrt_tcp_flow_add_with_drop(table_entry_ptr->src_ip, table_entry_ptr->dst_ip, table_entry_ptr->src_port, table_entry_ptr->dst_port);
#ifdef DO_STATS
				installed_entry_count_tot += res;
				installed_entry_count_tcp += res;
#endif

				break;
			}
			case IPPROTO_UDP:
			{
				res = bfrt_udp_flow_add_with_drop(table_entry_ptr->src_ip, table_entry_ptr->dst_ip, table_entry_ptr->src_port, table_entry_ptr->dst_port);
#ifdef DO_STATS
				installed_entry_count_tot += res;
				installed_entry_count_udp += res;
#endif
				break;
			}
			case IPPROTO_ICMP:
			{
				res = bfrt_icmp_flow_add_with_drop(table_entry_ptr->src_ip, table_entry_ptr->dst_ip);
#ifdef DO_STATS
				installed_entry_count_tot += res;
				installed_entry_count_icmp += res;
#endif
				break;
			}
			}
		}

#ifdef DO_STATS
		// gettimeofday(&end_time, NULL);
		// printf("entry_adding_time: %d\n", tv_sub_2(end_time, start_time));
#endif
		if (elapsed(last_idle_cleaned_time, current_time) > ENTRY_IDLE_TIMEOUT)
		{
			clean_all_idle_entries();
			last_idle_cleaned_time = current_time;
		}
#ifdef DO_STATS
		// gettimeofday(&end_time, NULL);
		// printf("cleaning time: %d\n", tv_sub_2(end_time, start_time));
#endif

#ifdef DO_STATS
		tcp_flow_entry_count = bfrt_get_table_usage("tcp_flow");
		udp_flow_entry_count = bfrt_get_table_usage("udp_flow");
		icmp_flow_entry_count = bfrt_get_table_usage("icmp_flow");

		// gettimeofday(&end_time, NULL);
		// printf("get_table_entry_num_time: %d\n", tv_sub_2(end_time, start_time));
#endif
	}

	PyGILState_Release(ret);
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
int bfrt_tcp_flow_add_with_drop(in_addr src_ip, in_addr dst_ip, u_short src_port, u_short dst_port)
{
	assert(pInstance != NULL);
	PyObject *pArgs, *pRes, *pFunc;
	char ip_src_addr_str[INET_ADDRSTRLEN], ip_dst_addr_str[INET_ADDRSTRLEN];
	int ret = 0;

	inet_ntop(AF_INET, &(src_ip), ip_src_addr_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(dst_ip), ip_dst_addr_str, INET_ADDRSTRLEN);

	pFunc = PyObject_GetAttrString(pInstance, "tcp_flow_add_with_drop");
	pArgs = Py_BuildValue("(ssii)", ip_src_addr_str, ip_dst_addr_str, ntohs(src_port), ntohs(dst_port));
	pRes = PyEval_CallObject(pFunc, pArgs);
	assert(pRes != NULL);
	PyArg_Parse(pRes, "i", &ret);
	Py_DECREF(pFunc);
	Py_DECREF(pArgs);
	Py_DECREF(pRes);
	return ret;
}

/* UDP Flow Table */
int bfrt_udp_flow_add_with_drop(in_addr src_ip, in_addr dst_ip, u_short src_port, u_short dst_port)
{
	assert(pInstance != NULL);
	PyObject *pArgs, *pRes, *pFunc;
	char ip_src_addr_str[INET_ADDRSTRLEN], ip_dst_addr_str[INET_ADDRSTRLEN];
	int ret = 0;

	inet_ntop(AF_INET, &(src_ip), ip_src_addr_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(dst_ip), ip_dst_addr_str, INET_ADDRSTRLEN);

	pFunc = PyObject_GetAttrString(pInstance, "udp_flow_add_with_drop");
	pArgs = Py_BuildValue("(ssii)", ip_src_addr_str, ip_dst_addr_str, ntohs(src_port), ntohs(dst_port));
	pRes = PyEval_CallObject(pFunc, pArgs);
	PyArg_Parse(pRes, "i", &ret);
	Py_DECREF(pFunc);
	Py_DECREF(pArgs);
	Py_DECREF(pRes);
	return ret;
}

/* ICMP Flow Table */
int bfrt_icmp_flow_add_with_drop(in_addr src_ip, in_addr dst_ip)
{
	assert(pInstance != NULL);
	PyObject *pArgs, *pRes, *pFunc;
	char ip_src_addr_str[INET_ADDRSTRLEN], ip_dst_addr_str[INET_ADDRSTRLEN];
	int ret = 0;

	inet_ntop(AF_INET, &(src_ip), ip_src_addr_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(dst_ip), ip_dst_addr_str, INET_ADDRSTRLEN);

	pFunc = PyObject_GetAttrString(pInstance, "icmp_flow_add_with_drop");
	pArgs = Py_BuildValue("(ss)", ip_src_addr_str, ip_dst_addr_str);
	pRes = PyEval_CallObject(pFunc, pArgs);
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

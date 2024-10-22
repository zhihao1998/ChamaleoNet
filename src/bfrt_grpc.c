#include "tsdn.h"

static PyObject *pModule, *pClass, *pInstance;
static table_entry_t **p4_entry_buf;
static circular_buf_t *p4_entry_circ_buf;
static pthread_mutex_t entry_install_mutex;
static pthread_cond_t entry_install_cond;
char ip_src_addr_str[INET_ADDRSTRLEN], ip_dst_addr_str[INET_ADDRSTRLEN];

u_long entry_circ_buf_size()
{
#ifdef SWITCH_ENABLED
	return circular_buf_size(p4_entry_circ_buf);
#else
	return 0;
#endif
}

int try_install_p4_entry(in_addr service_ip, ushort service_port, ushort service_protocol)
{

	table_entry_t *temp_table_entry_ptr, **temp_table_entry_pp;

	temp_table_entry_ptr = table_entry_alloc();
	temp_table_entry_ptr->service_ip = service_ip;
	temp_table_entry_ptr->service_port = service_port;
	temp_table_entry_ptr->service_protocol = service_protocol;
	assert(temp_table_entry_pp != NULL);

	fprintf(fp_log, "active,%s,%d,%d\n",
			inet_ntop(AF_INET, &temp_table_entry_ptr->service_ip, ip_src_addr_str, INET_ADDRSTRLEN),
			ntohs(temp_table_entry_ptr->service_port), 
			temp_table_entry_ptr->service_protocol);

	temp_table_entry_pp = (table_entry_t **)circular_buf_try_put(p4_entry_circ_buf, (void *)temp_table_entry_ptr);

	pthread_cond_signal(&entry_install_cond);
	return 0;
}

void *install_thead_main(void *args)
{
#ifdef SWITCH_ENABLED
	/* Initialize the P4 entry buffer */
	p4_entry_buf = (table_entry_t **)MallocZ(ENTRY_BUF_SIZE * sizeof(table_entry_t *));
	p4_entry_circ_buf = circular_buf_init((void **)p4_entry_buf, ENTRY_BUF_SIZE);

	bfrt_grpc_init();
	PyGILState_STATE py_state = PyGILState_Ensure();
	pthread_mutex_init(&entry_install_mutex, NULL);
	pthread_cond_init(&entry_install_cond, NULL);

	timeval start_time, end_time;
	active_host_tbl_entry_count = 0;
	table_entry_t *table_entry_ptr;

	PyObject *p_add_batch_Func = PyObject_GetAttrString(pInstance, "add_batch_entries");

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
		gettimeofday(&start_time, NULL);
#endif

		/* Install multiple entries at a time */
		int batch_size = 100;
		int batch_index = 0;
		if (circular_buf_size(p4_entry_circ_buf) > batch_size)
		{
			PyObject *entry_list = PyList_New(0);
			PyObject *ArgList = PyTuple_New(1);

			while (batch_index < batch_size)
			{
				int ret = circular_buf_get(p4_entry_circ_buf, &buf_slot);
				assert(ret == 0);

				PyObject *entry_key = PyList_New(3);
				table_entry_t *table_entry_ptr = (table_entry_t *)buf_slot;
				assert(table_entry_ptr != NULL);
				// printf("Installing (ip: %u ,port: %d, protocol: %d) to the entry buffer, size: %ld, head: %ld, tail: %ld\n",
				// 	   table_entry_ptr->service_ip.s_addr,
				// 	   ntohs(table_entry_ptr->service_port),
				// 	   table_entry_ptr->service_protocol,
				// 	   entry_circ_buf_size(), p4_entry_circ_buf->head, p4_entry_circ_buf->tail);

				PyList_SetItem(entry_key, 0, Py_BuildValue("I", ntohl(table_entry_ptr->service_ip.s_addr)));
				PyList_SetItem(entry_key, 1, Py_BuildValue("i", ntohs(table_entry_ptr->service_port)));
				PyList_SetItem(entry_key, 2, Py_BuildValue("i", table_entry_ptr->service_protocol));

				PyList_Append(entry_list, entry_key);

				table_entry_release(table_entry_ptr);

				batch_index++;
				Py_DECREF(entry_key);
			}

			PyTuple_SetItem(ArgList, 0, entry_list);
			PyObject_CallObject(p_add_batch_Func, ArgList);
			Py_DECREF(entry_list);
			Py_DECREF(ArgList);

			// gettimeofday(&end_time, NULL);
			// printf("Installing time: %d\n", tv_sub_2(end_time, start_time));

#ifdef DO_STATS
			installed_entry_count_tot += batch_index;
#endif
		}

		if (elapsed(last_idle_cleaned_time, current_time) > ENTRY_IDLE_TIMEOUT)
		{			
			clean_all_idle_entries();
			gettimeofday(&last_idle_cleaned_time, NULL);
		}

		active_host_tbl_entry_count = bfrt_get_table_usage();
		local_entry_count = bfrt_get_local_entry_number();
	}

	Py_DECREF(p_add_batch_Func);
	PyGILState_Release(py_state);
#endif
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
	PyArg_Parse(pRes, "i", &ret);
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

/* Get Entry Table Number */
int bfrt_get_table_usage()
{
	assert(pInstance != NULL);
	PyObject *pArgs, *pRes, *pFunc;
	int ret = -1;

	pFunc = PyObject_GetAttrString(pInstance, "get_table_usage");
	pArgs = Py_BuildValue("()");
	pRes = PyEval_CallObject(pFunc, pArgs);
	PyArg_Parse(pRes, "i", &ret);
	Py_DECREF(pFunc);
	Py_DECREF(pArgs);
	Py_DECREF(pRes);
	return ret;
}

/* Get Local Flow key number */
int bfrt_get_local_entry_number()
{
	assert(pInstance != NULL);
	PyObject *pArgs, *pRes, *pFunc;
	int ret = -1;

	pFunc = PyObject_GetAttrString(pInstance, "get_local_flow_entry_num");
	pArgs = Py_BuildValue("()");
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
